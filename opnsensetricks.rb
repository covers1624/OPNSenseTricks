#!/usr/bin/env ruby
require 'nokogiri'
require 'nokogiri/xml/node'
require 'json'
require 'optparse'
require 'ostruct'
require 'logger'
require 'net/http'
require 'openssl'

def main
  options = OpenStruct.new
  options.config_file = 'config.json'
  OptionParser.new do |opt|
    opt.on('-c', '--config CONFIG', String, 'Sets the config json for private data.') { |o| options.config_file = o }
    opt.on('-K', '--key KEY', String, "The Key file to use.") { |o| options.key_file = o }
    opt.on('-C', '--cert CERT', String, "The Cert file to use.") { |o| options.cert_file = o }
    opt.on('-f', '--output OUTPUT', String, "Sets the output file when backing up the config.") { |o| options.output = o }
    opt.on('-v', '--verbose', "Enables verbose logging.") { options.verbose = true }
    opt.on('-u', '--update-web-ui', "Updates the Web-UI's Key and certificate") { options.update_ui = true }
    opt.on('-b', '--backup-config', "Downloads a backup of the current config.") { options.backup = true }
  end.parse!

  key_file = options.key_file
  cert_file = options.cert_file
  output = options.output
  verbose = (options.verbose != nil) && options.verbose
  update = (options.update_ui != nil) && options.update_ui
  backup = (options.backup != nil) && options.backup

  logger_formatter = proc { |l, t, p, m| "[#{t.strftime("%H:%M:%S.%L")}] [#{l}]: #{m}\n" }
  logger_level = verbose ? Logger::DEBUG : Logger::INFO
  console_logger = Logger.new(STDOUT)
  console_logger.formatter = logger_formatter
  console_logger.level = logger_level
  file_logger = Logger.new("latest.log")
  file_logger.formatter = logger_formatter
  file_logger.level = Logger::DEBUG

  logger = MultiLogger.new(console_logger, file_logger)


  logger.debug("Starting OPNsenseTricks.")
  unless File.exists?(options.config_file) && File.file?(options.config_file)
    raise "File not found '#{options.config_file}'"
  end

  config = JSON.parse(File.read(options.config_file))

  check_exist(config, 'address', "Config missing")
  check_exist(config, 'username', "Config missing")
  check_exist(config, 'password', "Config missing")

  begin
    if update && backup
      raise "Both Update and Backup arguments specified, this is currently not supported."
    elsif update == backup
      raise "Please specify Update or Backup."
    end

    address = config['address']
    index_page = URI("https://#{address}/index.php")
    diag_backup_page = URI("https://#{address}/diag_backup.php")
    system_certmanager_page = URI("https://#{address}/system_certmanager.php")
    system_advanced_admin_page = URI("https://#{address}/system_advanced_admin.php")
    install_cert_page = URI("https://#{address}/install_cert.php")

    logger.info("Running login..")
    requester = Requester.new(false, logger)
    response = requester.req(index_page, :get)
    doc = Nokogiri::HTML(response.body).css("input[type=hidden]").first
    token = [doc['name'], doc['value']]

    data = [
        token,
        ["login", "1"],
        ["passwordfld", config['password']],
        ["usernamefld", config['username']]
    ]
    requester.req(index_page, :post, data)
    logger.info("Success!")

    if backup
      logger.info("Exporting config..")
      data = [
          token,
          ["donotbackuprrd", 'on'],
          ["download", 'Download']
      ]
      response = requester.req(diag_backup_page, :post, data)
      File.open(output, "wb") { |f| f.write(response.body) }
      logger.info("Success! Backup written to: #{output}")
    elsif update
      if key_file == nil || !File.file?(key_file) || !File.exists?(key_file)
        raise "KeyFile not specified or doesnt exist."
      end
      if cert_file == nil || !File.file?(cert_file) || !File.exists?(cert_file)
        raise "CertFile not specified or doesnt exist."
      end
      logger.info("Updating WebUI Certificate.")
      logger.debug("Key file: #{key_file}")
      logger.debug("Certificate file: #{cert_file}")
      cert_name = "Ruby Uploaded Certificate: #{random_str(6)}"
      logger.debug("Certificate name: #{cert_name}")

      logger.info("Uploading new certificate with name: '#{cert_name}'")
      upload_req = [
          token,
          ["act", "new"],
          ["certmethod", "import"],
          ["descr", cert_name],
          ["cert", File.read(cert_file)],
          ["key", File.read(key_file)],
          ["save", "Save"]
      ]
      requester.req(system_certmanager_page, :get)
      requester.req(system_certmanager_page, :post, upload_req)
      logger.info("Certificate uploaded.")

      logger.info("Retrieving cert-ref.")
      response = requester.req(system_advanced_admin_page, :get)
      doc = Nokogiri::HTML(response.body).css("select[name=ssl-certref]").first
      certs = {}
      doc.children.each do |option|
        if option.element?
          certs[option.children.first.content.strip] = option['value']
        end
      end
      logger.debug("Found the following certificates #{certs}")
      cert_id = certs[cert_name]
      if cert_id == nil
        raise "Unable to find cert id."
      end
      logger.debug("Our cert id is: #{cert_id}")
      logger.info("Installing the new certificate.")
      install_req = [
          token,
          ["ssl-certref", cert_id]
      ]
      requester.req(install_cert_page, :post, install_req)
      logger.info("Success!")
    end
  rescue => err
    console_logger.close
    file_logger.close
    raise err
  end
end

def check_exist(table, key, prefix = "Missing key")
  unless table.key?(key)
    raise "#{prefix} '#{key}'."
  end
end

def is_boolean?(value)
  [true, false].include? value
end

def random_str(len)
  o = [('a'..'z'), ('A'..'Z'), (0..9)].map(&:to_a).flatten
  (0...len).map { o[rand(o.length)] }.join
end

class Requester

  def initialize(verify, logger)
    unless is_boolean?(verify)
      raise "Expected boolean."
    end
    @cookies = {}
    @verify = verify ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE
    @logger = logger
  end

  def req(uri, method, data = [])
    Net::HTTP.start(uri.host, uri.port, :use_ssl => uri.scheme == 'https', :verify_mode => @verify) do |http|
      if method == :post
        encoded = URI.encode_www_form(data)
        request = Net::HTTP::Post.new(uri)
        request['Conent-Length'] = encoded.length
        request.body = encoded
        @logger.debug("Post, URI: #{uri}, Data: #{request}")
      else
        request = Net::HTTP::Get.new(uri)
      end
      request['Cookie'] = @cookies.keys.map { |k| k + "=" + @cookies[k] }.join(";")

      response = http.request(request)
      @logger.debug("Response: #{response.inspect}, #{response.body}")
      if '4' == (response.code[0])
        puts request.inspect
        puts response.inspect
        puts response.body
        raise "#{response.code}"
      end

      if response['Set-Cookie']
        cookies = response['Set-Cookie'].split(",").map { |x| x.strip.scan(/([a-zA-Z_]+)=([a-zA-Z0-9]+).*/) }.map(&:first).to_h
        @cookies.merge! cookies
      end
      response
    end
  end
end

class MultiLogger
  def initialize(*targets)
    @targets = targets
  end

  %w(log debug info warn error fatal unknown).each do |m|
    define_method(m) do |*args|
      @targets.map { |t| t.send(m, *args) }
    end
  end
end

main
