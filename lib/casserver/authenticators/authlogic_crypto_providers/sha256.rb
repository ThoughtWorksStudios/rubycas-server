require "digest/sha2"

module Authlogic
  # The acts_as_authentic method has a crypto_provider option. This allows you to use any type of encryption you like.
  # Just create a class with a class level encrypt and matches? method. See example below.
  #
  # === Example
  #
  #   class MyAwesomeEncryptionMethod
  #     def self.encrypt(*tokens)
  #       # the tokens passed will be an array of objects, what type of object is irrelevant,
  #       # just do what you need to do with them and return a single encrypted string.
  #       # for example, you will most likely join all of the objects into a single string and then encrypt that string
  #     end
  #
  #     def self.matches?(crypted, *tokens)
  #       # return true if the crypted string matches the tokens.
  #       # depending on your algorithm you might decrypt the string then compare it to the token, or you might
  #       # encrypt the tokens and make sure it matches the crypted string, its up to you
  #     end
  #   end
  module CryptoProviders
    # = Sha512
    #
    # Uses the Sha512 hash algorithm to encrypt passwords.
    class Sha256
      class << self
        # Turns your raw password into a Sha512 hash.
        def encrypt(*tokens)
          tokens = tokens.flatten
          Digest::SHA256.hexdigest("#{tokens.second}#{tokens.first}")
        end

        # Does the crypted password match the tokens? Uses the same tokens that were used to encrypt.
        def matches?(crypted, *tokens)
          encrypt(*tokens) == crypted
        end
      end
    end
  end
end
