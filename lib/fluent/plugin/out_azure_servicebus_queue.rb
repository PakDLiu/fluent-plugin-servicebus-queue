require 'fluent/plugin/output'
require "cgi"
require 'openssl'
require "base64"
require 'net/http'

module Fluent::Plugin
  class AzureServicebusQueue < Output
    Fluent::Plugin.register_output("azure_servicebus_queue", self)

    helpers :formatter, :compat_parameters

    config_param :namespace, :string
    config_param :queueName, :string
    config_param :accessKeyName, :string
    config_param :accessKeyValueFile, :string

    attr_accessor :formatter

    def configure(conf)
      compat_parameters_convert(conf, :formatter)
      super
      @formatter = formatter_create
    end

    # method for sync buffered output mode
    def write(chunk)
      read = chunk.read()
      split = read.split("\n")

      request = createRequest

      split.each do |line|
        log.debug "processing line: ", line

        request.body = line
        https.request(request)
      end
    end

    # method for custom format
    def format(tag, time, record)
      @formatter.format(tag, time, record).chomp + "\n"
    end

    def createRequest()
      url = "https://#{namespace}.servicebus.windows.net/#{queueName}/messages"
      keyValue = getAccessKeyValue
      token = generateToken(url, accessKeyName, keyValue)

      uri = URI.parse(url)
      https = Net::HTTP.new(uri.host, uri.port)
      https.use_ssl = true
      https.verify_mode = OpenSSL::SSL::VERIFY_NONE
      request = Net::HTTP::Post.new(uri.request_uri)
      request['Content-Type'] = 'application/json'
      request['Authorization'] = token

      request
    end

    def getAccessKeyValue
      File.read(accessKeyValueFile).strip
    end

    def generateToken(url,key_name,key_value)
      target_uri = CGI.escape(url.downcase).gsub('+', '%20').downcase
      expires = Time.now.to_i + 10
      to_sign = "#{target_uri}\n#{expires}"

      signature = CGI.escape(
          Base64.strict_encode64(
            OpenSSL::HMAC.digest(
              OpenSSL::Digest.new('sha256'), key_value, to_sign
            )
          )
        ).gsub('+', '%20')

      "SharedAccessSignature sr=#{target_uri}&sig=#{signature}&se=#{expires}&skn=#{key_name}"
    end
  end
end