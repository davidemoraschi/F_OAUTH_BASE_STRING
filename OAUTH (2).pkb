CREATE OR REPLACE PACKAGE BODY ALMAGESTO.oauth
AS
   FUNCTION base_string (
      p_http_method         IN   VARCHAR2
     ,p_request_token_url   IN   VARCHAR2
     ,p_consumer_key        IN   VARCHAR2
     ,p_timestamp           IN   VARCHAR2
     ,p_nonce               IN   VARCHAR2)
      RETURN VARCHAR2
   AS
      v_oauth_base_string           VARCHAR2 (2000);
   BEGIN
      SELECT    p_http_method
             || '&'
             || urlencode (p_request_token_url)
             || '&'
             || urlencode (   'oauth_callback'
                           || '='
                           || 'oob'
                           || '&'
                           || 'oauth_consumer_key'
                           || '='
                           || urlencode (p_consumer_key)
                           || '&'
                           || 'oauth_nonce'
                           || '='
                           || p_nonce
                           || '&'
                           || 'oauth_signature_method'
                           || '='
                           || 'HMAC-SHA1'
                           || '&'
                           || 'oauth_timestamp'
                           || '='
                           || p_timestamp
                           || '&'
                           || 'oauth_version'
                           || '='
                           || '1.0')
      INTO   v_oauth_base_string
      FROM   DUAL;

      RETURN v_oauth_base_string;
   END base_string;

   FUNCTION base_string_token (
      p_http_method         IN   VARCHAR2
     ,p_request_token_url   IN   VARCHAR2
     ,p_consumer_key        IN   VARCHAR2
     ,p_timestamp           IN   VARCHAR2
     ,p_nonce               IN   VARCHAR2
     ,p_token               IN   VARCHAR2
     ,p_token_verifier      IN   VARCHAR2)
      RETURN VARCHAR2
   AS
      v_oauth_base_string           VARCHAR2 (2000);
   BEGIN
      SELECT    p_http_method
             || '&'
             || urlencode (p_request_token_url)
             || '&'
             || urlencode (   'oauth_callback'
                           || '='
                           || 'oob'
                           || '&'
                           || 'oauth_consumer_key'
                           || '='
                           || urlencode (p_consumer_key)
                           || '&'
                           || 'oauth_nonce'
                           || '='
                           || p_nonce
                           || '&'
                           || 'oauth_signature_method'
                           || '='
                           || 'HMAC-SHA1'
                           || '&'
                           || 'oauth_timestamp'
                           || '='
                           || p_timestamp
                           || '&'
                           || 'oauth_token'
                           || '='
                           || urlencode (p_token)
                           || '&'
                           || 'oauth_verifier'
                           || '='
                           || p_token_verifier
                           || '&'
                           || 'oauth_version'
                           || '='
                           || '1.0')
      INTO   v_oauth_base_string
      FROM   DUAL;

      RETURN v_oauth_base_string;
   END base_string_token;

   FUNCTION base_string_access_token (
      p_http_method         IN   VARCHAR2
     ,p_request_token_url   IN   VARCHAR2
     ,p_consumer_key        IN   VARCHAR2
     ,p_timestamp           IN   VARCHAR2
     ,p_nonce               IN   VARCHAR2
     ,p_token               IN   VARCHAR2)
      RETURN VARCHAR2
   AS
         /*
          oauth_consumer_key
          oauth_nonce
          oauth_signature_method
          oauth_timestamp
          oauth_version

          oauth_signature

          action=user-get
          response=xml

      */
      v_oauth_base_string           VARCHAR2 (2000);
   BEGIN
      SELECT    p_http_method
             || '&'
             || urlencode (p_request_token_url)
             || '&'
             || urlencode (   'oauth_consumer_key'
                           || '='
                           || urlencode (p_consumer_key)
                           || '&'
                           || 'oauth_nonce'
                           || '='
                           || p_nonce
                           || '&'
                           || 'oauth_signature_method'
                           || '='
                           || 'HMAC-SHA1'
                           || '&'
                           || 'oauth_timestamp'
                           || '='
                           || p_timestamp
                           || '&'
                           || 'oauth_token'
                           || '='
                           || urlencode (p_token)
                           || '&'
                           || 'oauth_version'
                           || '='
                           || '1.0')
      INTO   v_oauth_base_string
      FROM   DUAL;

      RETURN v_oauth_base_string;
   END base_string_access_token;

   FUNCTION KEY (p_consumer_secret IN VARCHAR2)
      RETURN VARCHAR2
   AS
      v_oauth_key                   VARCHAR2 (500);
   BEGIN
      SELECT urlencode (p_consumer_secret) || '&'
      INTO   v_oauth_key
      FROM   DUAL;

      RETURN v_oauth_key;
   END KEY;

   FUNCTION key_token (p_consumer_secret IN VARCHAR2, p_token_secret IN VARCHAR2)
      RETURN VARCHAR2
   AS
      v_oauth_key                   VARCHAR2 (500);
   BEGIN
      SELECT urlencode (p_consumer_secret) || '&' || urlencode (p_token_secret)                                  --giá urlencodato
      INTO   v_oauth_key
      FROM   DUAL;

      RETURN v_oauth_key;
   END key_token;

   FUNCTION signature (p_oauth_base_string IN VARCHAR2, p_oauth_key IN VARCHAR2)
      RETURN VARCHAR2
   AS
      v_oauth_signature             VARCHAR2 (500);
   BEGIN
      v_oauth_signature :=
         UTL_RAW.cast_to_varchar2 (UTL_ENCODE.base64_encode (DBMS_CRYPTO.mac (UTL_I18N.string_to_raw (p_oauth_base_string
                                                                                                     ,'AL32UTF8')
                                                                             ,DBMS_CRYPTO.hmac_sh1
                                                                             ,UTL_I18N.string_to_raw (p_oauth_key, 'AL32UTF8'))));
      RETURN v_oauth_signature;
   END signature;

   FUNCTION http_req_url (
      p_request_token_url   IN   VARCHAR2
     ,p_consumer_key        IN   VARCHAR2
     ,p_timestamp           IN   VARCHAR2
     ,p_nonce               IN   VARCHAR2
     ,p_signature           IN   VARCHAR2)
      RETURN VARCHAR2
   AS
      v_http_req_url                VARCHAR2 (4000);
   BEGIN
      v_http_req_url :=
            p_request_token_url
         || '?'
         || 'oauth_callback'
         || '='
         || 'oob'
         || '&'
         || 'oauth_consumer_key'
         || '='
         || p_consumer_key
         || '&'
         || 'oauth_nonce'
         || '='
         || p_nonce
         || '&'
         || 'oauth_signature'
         || '='
         || urlencode (p_signature)
         || '&'
         || 'oauth_signature_method'
         || '='
         || 'HMAC-SHA1'
         || '&'
         || 'oauth_timestamp'
         || '='
         || p_timestamp
         || '&'
         || 'oauth_version'
         || '='
         || '1.0';
      RETURN v_http_req_url;
   END http_req_url;

   FUNCTION http_req_url_token (
      p_request_token_url   IN   VARCHAR2
     ,p_consumer_key        IN   VARCHAR2
     ,p_timestamp           IN   VARCHAR2
     ,p_nonce               IN   VARCHAR2
     ,p_signature           IN   VARCHAR2
     ,p_token               IN   VARCHAR2
     ,p_token_verifier      IN   VARCHAR2)
      RETURN VARCHAR2
   AS
      v_http_req_url                VARCHAR2 (4000);
   BEGIN
      v_http_req_url :=
            p_request_token_url
         || '?'
         || 'oauth_callback'
         || '='
         || 'oob'
         || '&'
         || 'oauth_consumer_key'
         || '='
         || p_consumer_key
         || '&'
         || 'oauth_nonce'
         || '='
         || p_nonce
         || '&'
         || 'oauth_signature'
         || '='
         || urlencode (p_signature)
         || '&'
         || 'oauth_signature_method'
         || '='
         || 'HMAC-SHA1'
         || '&'
         || 'oauth_timestamp'
         || '='
         || p_timestamp
         || '&'
         || 'oauth_token'
         || '='
         || urlencode (p_token)
         || '&'
         || 'oauth_verifier'
         || '='
         || p_token_verifier
         || '&'
         || 'oauth_version'
         || '='
         || '1.0';
      RETURN v_http_req_url;
   END http_req_url_token;

   FUNCTION http_req_url_access_token (
      p_request_token_url   IN   VARCHAR2
     ,p_consumer_key        IN   VARCHAR2
     ,p_timestamp           IN   VARCHAR2
     ,p_nonce               IN   VARCHAR2
     ,p_signature           IN   VARCHAR2
     ,p_token               IN   VARCHAR2)
      RETURN VARCHAR2
   AS
      v_http_req_url                VARCHAR2 (4000);
   BEGIN
      v_http_req_url :=
            p_request_token_url
         || '?'
         || 'oauth_callback'
         || '='
         || 'oob'
         || '&'
         || 'oauth_consumer_key'
         || '='
         || p_consumer_key
         || '&'
         || 'oauth_nonce'
         || '='
         || p_nonce
         || '&'
         || 'oauth_signature'
         || '='
         || urlencode (p_signature)
         || '&'
         || 'oauth_signature_method'
         || '='
         || 'HMAC-SHA1'
         || '&'
         || 'oauth_timestamp'
         || '='
         || p_timestamp
         || '&'
         || 'oauth_token'
         || '='
         || p_token
         || '&'
         || 'oauth_version'
         || '='
         || '1.0';
      RETURN v_http_req_url;
   END http_req_url_access_token;

   FUNCTION get_token (the_list VARCHAR2, the_index NUMBER, delim VARCHAR2 := ',')
      RETURN VARCHAR2
   IS
      start_pos                     NUMBER;
      end_pos                       NUMBER;
   BEGIN
      IF the_index = 1
      THEN
         start_pos := 1;
      ELSE
         start_pos := INSTR (the_list, delim, 1, the_index - 1);

         IF start_pos = 0
         THEN
            RETURN NULL;
         ELSE
            start_pos := start_pos + LENGTH (delim);
         END IF;
      END IF;

      end_pos := INSTR (the_list, delim, start_pos, 1);

      IF end_pos = 0
      THEN
         RETURN SUBSTR (the_list, start_pos);
      ELSE
         RETURN SUBSTR (the_list, start_pos, end_pos - start_pos);
      END IF;
   END get_token;

   FUNCTION authorization_header (
      p_consumer_key   IN   VARCHAR2
     ,p_token          IN   VARCHAR2
     ,p_timestamp      IN   VARCHAR2
     ,p_nonce          IN   VARCHAR2
     ,p_signature      IN   VARCHAR2)
      RETURN VARCHAR2
   IS
      v_authorization_header        VARCHAR2 (4000);
   BEGIN
      v_authorization_header :=
            'OAuth realm="",oauth_version="1.0",oauth_consumer_key="'
         || p_consumer_key
         || '",oauth_token="'
         || p_token
         || '",oauth_timestamp="'
         || p_timestamp
         || '",oauth_nonce="'
         || p_nonce
         || '",oauth_signature_method="HMAC-SHA1",oauth_signature="'
         || urlencode (p_signature)
         || '"';
      RETURN v_authorization_header;
   END authorization_header;

   FUNCTION authorization_header_no_token (
      p_consumer_key   IN   VARCHAR2
     ,p_timestamp      IN   VARCHAR2
     ,p_nonce          IN   VARCHAR2
     ,p_signature      IN   VARCHAR2)
      RETURN VARCHAR2
   IS
      v_authorization_header        VARCHAR2 (4000);
   BEGIN
      v_authorization_header :=
            'OAuth realm="",oauth_callback="oob",oauth_version="1.0",oauth_consumer_key="'
         || p_consumer_key
         || '",oauth_timestamp="'
         || p_timestamp
         || '",oauth_nonce="'
         || p_nonce
         || '",oauth_signature_method="HMAC-SHA1",oauth_signature="'
         || urlencode (p_signature)
         || '"';
      RETURN v_authorization_header;
   END authorization_header_no_token;
END oauth;
/
