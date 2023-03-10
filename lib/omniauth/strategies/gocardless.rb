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
	

      # NOTE: We call redirect_params AFTER super in these methods intentionally
      # the OAuth2 strategy uses the authorize_params and token_params methods
      # to set up some state for testing that we need in redirect_params

      def authorize_params
        params = super
        params = params.merge(request_params) unless OmniAuth.config.test_mode
        redirect_params.merge(params)
      end

      def token_params
       params = super.to_hash(:symbolize_keys => true) \
          .merge(:headers => { 'Authorization' => "Bearer #{client.secret}" })

        redirect_params.merge(params)
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def request_phase
        redirect client.auth_code.authorize_url(authorize_params)
      end

      def build_access_token
        verifier = request.params['code']
        client.auth_code.get_token(verifier, token_params)
      end

      def request_params
        request.params.except(*request_blacklisted_params)
      end

      def request_blacklisted_params
        %w(_method)
      end
		
		
		end
	end
end
