require 'openssl'
require 'base64'

require 'strongbox/lock'
require 'strongbox/version'

module Strongbox
  RSA_PKCS1_PADDING      = OpenSSL::PKey::RSA::PKCS1_PADDING
  RSA_SSLV23_PADDING     = OpenSSL::PKey::RSA::SSLV23_PADDING
  RSA_NO_PADDING         = OpenSSL::PKey::RSA::NO_PADDING
  RSA_PKCS1_OAEP_PADDING = OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING

  class << self
    # Provides for setting the default options for Strongbox
    def options
      @options ||= {
        base64: false,
        symmetric: :always,
        padding: RSA_PKCS1_OAEP_PADDING,
        symmetric_cipher: 'aes-256-cbc',
        ensure_required_columns: true,
        deferred_encryption: false
      }
    end

    def included base #:nodoc:
      base.extend ClassMethods
      base.class_attribute :lock_options
      base.lock_options ||= {}
    end
  end

  class StrongboxError < StandardError #:nodoc:
  end

  module ClassMethods
    # +encrypt_with_public_key+ gives the class it is called on an attribute that
    # when assigned is automatically encrypted using a public key.  This allows the
    # unattended encryption of data, without exposing the information need to decrypt
    # it (as would be the case when using symmetric key encryption alone).  Small
    # amounts of data may be encrypted directly with the public key.  Larger data is
    # encrypted using symmetric encryption. The encrypted data is stored in the
    # database column of the same name as the attibute.  If symmetric encryption is
    # used (the default) additional column are need to store the generated password
    # and IV.
    #
    # Last argument should be the options hash
    # Argument 0..-2 contains columns to be encrypted
    def encrypt_with_public_key(*args)
      include InstanceMethods

      options = args.last.is_a?(Hash) ? args.pop : {}
      name    = args.shift

      lock_options[name] = Strongbox.options.merge options.symbolize_keys

      define_method name do
        lock_for(name)
      end

      define_method "#{name}=" do |plaintext|
        lock_for(name).content plaintext
      end

      if lock_options[name][:deferred_encryption]
        before_save do
          lock_for(name).encrypt!
        end
      end

      args.each{ |arg| encrypt_with_public_key(arg, options) }
    end
  end

  module InstanceMethods
    def lock_for name
      @_locks ||= {}
      @_locks[name] ||= Lock.new(name, self, self.class.lock_options[name])
    end
  end
end

# Load rails support
require 'strongbox/railtie' if defined?(Rails)
