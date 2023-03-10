require 'omniauth-oauth2'

module OmniAuth
	module Strategies
		class Gocardless < OmniAuth::Strategies::OAuth2

			option :name, :gocardless

			option :client_options, {
				:site => "https://connect.gocardless.com",
		        :authorize_url => '/oauth/authorize',
		        :token_url => '/oauth/access_token'
			}
		

			uid { access_token.params['organisation_id'] }

      info do
        {
          email: access_token.params['email']
        }
      end

			# Required for omniauth-oauth2 >= 1.4
			# https://github.com/intridea/omniauth-oauth2/issues/81
			def callback_url
				full_host + script_name + callback_path
			end

		credentials do
        hash = {'token' => access_token.token}
        hash.merge!('refresh_token' => access_token.refresh_token) if access_token.refresh_token
        hash.merge!('expires_at' => access_token.expires_at) if access_token.expires?
        hash.merge!('expires' => access_token.expires?)
        hash
      end
		
		
		end
	end
end
