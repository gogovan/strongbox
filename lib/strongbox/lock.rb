require 'encryptor'

module Strongbox
  # The Lock class encrypts and decrypts the protected attribute.  It
  # automatically encrypts the data when set and decrypts it when the private
  # key password is provided.
  class Lock

    def initialize(name, instance, options = {})
      @name = name
      @instance = instance

      @size = 0
      @raw_content = nil

      options = Strongbox.options.merge(options)

      @base64 = options[:base64]
      @public_key = options[:public_key] || options[:key_pair]
      @private_key = options[:private_key] || options[:key_pair]
      @padding = options[:padding]
      @symmetric = options[:symmetric]
      @symmetric_cipher = options[:symmetric_cipher]
      @symmetric_key = options[:symmetric_key] || "#{name}_key"
      @symmetric_iv = options[:symmetric_iv] || "#{name}_iv"
      @symmetric_salt = options[:symmetric_salt] || "#{name}_salt"
      @symmetric_auth_data = options[:symmetric_auth_data].to_s
      @ensure_required_columns = options[:ensure_required_columns]
      @deferred_encryption = options[:deferred_encryption]
    end

    def content(plaintext)
      @size = plaintext.to_s.size # For validations

      if @deferred_encryption
        @raw_content = plaintext
      else
        encrypt plaintext
      end
    end

    def encrypt!
      encrypt @raw_content
      @raw_content = nil
    end

    def encrypt(plaintext, options = {})
      ensure_required_columns

      return plaintext if plaintext.blank?

      unless @public_key
        raise StrongboxError.new("#{@instance.class} model does not have public key_file")
      end

      # Using a blank password in OpenSSL::PKey::RSA.new prevents reading
      # the private key if the file is a key pair
      public_key = get_rsa_key(@public_key)

      if symmetric?
        # default byte sizes for aes-256-gcm
        random_key  = options[:key]  || SecureRandom.random_bytes(32)
        random_iv   = options[:iv]   || SecureRandom.random_bytes(@symmetric_cipher =~ /gcm/ ? 12 : 16)
        random_salt = options[:salt] || SecureRandom.random_bytes(16)

        ciphertext  = Encryptor.encrypt(plaintext,
                        algorithm: @symmetric_cipher,
                        key: random_key,
                        iv: random_iv,
                        salt: random_salt,
                        auth_data: @symmetric_auth_data
                      )

        @instance[@symmetric_key]  = encode(public_key.public_encrypt(random_key, @padding))
        @instance[@symmetric_iv]   = encode(public_key.public_encrypt(random_iv, @padding))
        @instance[@symmetric_salt] = encode(public_key.public_encrypt(random_salt, @padding))
      else
        ciphertext = public_key.public_encrypt(plaintext, @padding)
      end

      @instance[@name] = encode(ciphertext)
    end

    # Given the private key password decrypts the attribute.  Will raise
    # OpenSSL::PKey::RSAError if the password is wrong.

    def decrypt(password = nil, ciphertext = @instance[@name])
      return @raw_content if @deferred_encryption && @raw_content

      # Given a private key and a nil password OpenSSL::PKey::RSA.new() will
      # *prompt* for a password, we default to an empty string to avoid that.

      return "*encrypted*" if password.nil?
      return ciphertext    if ciphertext.nil? || ciphertext.empty?

      unless @private_key
        raise StrongboxError.new("#{@instance.class} model does not have private key_file")
      end

      private_key = get_rsa_key(@private_key, password)

      if symmetric?

        plaintext = Encryptor.decrypt(decode(ciphertext),
                      algorithm: @symmetric_cipher,
                      key: private_key.private_decrypt(decode(@instance[@symmetric_key]), @padding),
                      iv: private_key.private_decrypt(decode(@instance[@symmetric_iv]), @padding),
                      salt: private_key.private_decrypt(decode(@instance[@symmetric_salt]), @padding),
                      auth_data: @symmetric_auth_data
                    )
      else
        plaintext = private_key.private_decrypt(decode(ciphertext), @padding)
      end

      plaintext
    end

    def symmetric?
      @symmetric == :always
    end

    def to_s
      @raw_content || decrypt
    end

    def to_json(options = nil)
      to_s
    end

    # Needed for validations
    def blank?
      @raw_content.blank? && @instance[@name].blank?
    end

    def nil?
      @raw_content.nil? && @instance[@name].nil?
    end

    def size
      @size
    end

    def length
      @size
    end

    def encode(value)
      @base64 ? Base64.encode64(value) : value
    end

    def decode(value)
      @base64 ? Base64.decode64(value) : value
    end

    def ensure_required_columns
      return unless @ensure_required_columns

      columns = [@name.to_s]
      columns += [@symmetric_key, @symmetric_iv] if symmetric?
      columns.each do |column|
        unless @instance.class.column_names.include? column
          raise StrongboxError.new("#{@instance.class} model does not have database column \"#{column}\"")
        end
      end
    end

  private

    def get_rsa_key(key, password = nil)
      return key if key.is_a?(OpenSSL::PKey::RSA)

      if key.is_a?(Proc)
        key = key.call
      elsif key.is_a?(Symbol)
        key = @instance.send(key)
      elsif key.respond_to?(:read)
        key = key.read
      elsif key !~ /^-+BEGIN .* KEY-+$/
        key = File.read(key)
      end

      if password.nil?
        OpenSSL::PKey::RSA.new(key)
      else
        OpenSSL::PKey::RSA.new(key, password)
      end
    end
  end
end
