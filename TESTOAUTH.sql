/* Formatted on 2010/08/10 15:14 (Formatter Plus v4.8.8) */
/*OFICIAL BASE_STRING CHECKED WITH NETFLIX API TESTER */

SET LINES 132
SET DEFINE OFF
SELECT oauth_base_string
FROM   DUAL;
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
       || urlencode ('&oauth_version=1.0') base_string
FROM   DUAL;

SELECT oauth_key
FROM   DUAL;


SELECT oauth.signature
FROM   DUAL;
