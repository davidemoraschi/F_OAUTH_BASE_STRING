/* Formatted on 2010/08/10 15:15 (Formatter Plus v4.8.8) */
CREATE OR REPLACE FUNCTION oauth_base_string
   RETURN VARCHAR2
AS
   v_oauth_base_string           VARCHAR2 (2000);
BEGIN
   SELECT    'GET&'
          || urlencode ('http://1daylater.com/get_request_token')
          || '&'
          || urlencode ('oauth_callback=oob')
          || urlencode ('&oauth_consumer_key=' || urlencode ('NHx8CZzuf9XEF6C2ksimwDkS7Fw='))
          || urlencode ('&oauth_nonce=' || oauth_nonce_seq.NEXTVAL)
          || urlencode ('&oauth_signature_method=HMAC-SHA1')
          || urlencode (   '&oauth_timestamp='
                        || TO_CHAR (  (SYSDATE - TO_DATE ('01-01-1970', 'DD-MM-YYYY')) * (86400)
                                    - (TO_NUMBER (SUBSTR (SESSIONTIMEZONE, 2, 2)) * 3600)))
          || urlencode ('&oauth_version=1.0')
   INTO   v_oauth_base_string
   FROM   DUAL;

   RETURN v_oauth_base_string;
END;