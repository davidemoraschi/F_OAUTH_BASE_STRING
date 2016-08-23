SET LINES 132
SET SERVEROUTPUT ON
SET DEFINE OFF
SET DEFINE #
SET VERIFY OFF
ACCEPT oauth_token PROMPT "Enter oauth_token obtained in step 2: "
ACCEPT oauth_token_secret PROMPT "Enter oauth_token_secret obtained in step 2: "

CREATE function urlencode( p_str in varchar2 ) return varchar2
as
    l_tmp   varchar2(6000);
    l_bad   varchar2(100) default ' >%}\~];?@&<#{|^[`/:=$+''"';
    l_char  char(1);
begin
    for i in 1 .. nvl(length(p_str),0) loop
        l_char :=  substr(p_str,i,1);
        if ( instr( l_bad, l_char ) > 0 )
        then
            l_tmp := l_tmp || '%' ||
                            to_char( ascii(l_char), 'fmXX' );
        else
            l_tmp := l_tmp || l_char;
        end if;
    end loop;

    return l_tmp;
end;
/
CREATE SEQUENCE oauth_nonce_seq MAXVALUE 9999 CYCLE;
DECLARE
   oauth_get_request_token_url          CONSTANT VARCHAR2 (1000) := 'http://1daylater.com/get_request_token';
   oauth_authorize_url                  CONSTANT VARCHAR2 (1000) := 'http://1daylater.com/authorize';
   oauth_get_access_token_url           CONSTANT VARCHAR2 (1000) := 'http://1daylater.com/get_access_token';
   oauth_api_url			CONSTANT VARCHAR2 (1000) := 'http://1daylater.com/api';
   
   oauth_callback                       CONSTANT VARCHAR2 (1000) := 'oob';
   oauth_consumer_key                   CONSTANT VARCHAR2 (50)   := urlencode ('NHx8CZzuf9XEF6C2ksimwDkS7Fw=');
   oauth_nonce                                   VARCHAR2 (50);
   oauth_signature_method               CONSTANT VARCHAR2 (10)   := urlencode ('HMAC-SHA1');
   oauth_timestamp                               VARCHAR2 (50);
   oauth_timestamp_offset                        VARCHAR2 (50)   := to_number(substr(sessiontimezone,2,2))*3600;

   oauth_version                        CONSTANT VARCHAR2 (5)    := urlencode ('1.0');
   oauth_consumer_secret                CONSTANT VARCHAR2 (50)   := '7XF7YN/rNzYcqDlJFsTqyC81KWw=';
   oauth_token                                   VARCHAR2 (500)  := urlencode ('sFEBFitHCRFGHTaX3Xm/TtUNUH4=');
   oauth_token_secret                            VARCHAR2 (500)  := 'MEV8f6AIehwKeuX9Qw1y6jWAoWw=';

   oauth_base_string                             VARCHAR2 (4000);
   oauth_key                                     VARCHAR2 (500) ;
   oauth_signature                               VARCHAR2 (100);

   l_sig_mac                                     RAW (2000);

   http_post_data                                VARCHAR2 (4000);
   http_method                                   VARCHAR2 (5) := 'POST';
   http_req                                      UTL_HTTP.req;
   http_resp                                     UTL_HTTP.resp;

   h_name                                        VARCHAR2 (255);
   h_value                                       VARCHAR2 (1023);
   res_value                                     VARCHAR2 (32767);
   show_header                                   NUMBER := 1;
   show_xml                                      NUMBER := 1;

BEGIN

   SELECT urlencode (oauth_nonce_seq.NEXTVAL)
   INTO   oauth_nonce
   FROM   DUAL;

   SELECT urlencode ((SYSDATE - TO_DATE ('01-01-1970', 'DD-MM-YYYY')) * (86400) - oauth_timestamp_offset)
   INTO   oauth_timestamp
   FROM   DUAL;

   oauth_base_string :=
         http_method
      || '&'
      || urlencode (oauth_api_url)
      || '&'
      || urlencode (
                       'action=user-get'
                    || '&'
	            || 'oauth_consumer_key'
                    || '='
                    || oauth_consumer_key
                    || '&'
                    || 'oauth_nonce'
                    || '='
                    || oauth_nonce
                    || '&'
                    || 'oauth_signature_method'
                    || '='
                    || oauth_signature_method
                    || '&'
                    || 'oauth_timestamp'
                    || '='
                    || oauth_timestamp
                    || '&'
                    || 'oauth_token'
                    || '='
                    || oauth_token
                    || '&'
                    || 'oauth_version'
                    || '='
                    || oauth_version
                    || '&'
		    || 'response=xml');

   oauth_key := urlencode(oauth_consumer_secret) || '&' || urlencode(oauth_token_secret);
   l_sig_mac := DBMS_CRYPTO.mac (UTL_I18N.string_to_raw (oauth_base_string, 'AL32UTF8')
                      ,DBMS_CRYPTO.hmac_sh1, UTL_I18N.string_to_raw (oauth_key, 'AL32UTF8'));
   oauth_signature := UTL_RAW.cast_to_varchar2 (UTL_ENCODE.base64_encode (l_sig_mac));

   http_post_data :=
         'Authorization: OAuth  '
      || 'oauth_consumer_key="'
      || urlencode(oauth_consumer_key)
      || '", oauth_nonce="'
      || urlencode(oauth_nonce)
      || '", oauth_signature="'
      || urlencode(oauth_signature)
      || '", oauth_signature_method="'
      || urlencode(oauth_signature_method)
      || '", oauth_timestamp="'
      || urlencode(oauth_timestamp)
      || '", oauth_token="'
      || urlencode(oauth_token)
      || '", oauth_version="'
      || urlencode(oauth_version)
      || '", action="user-get",response="xml"';

   /* in case it's needed set proxy */
   /*+++++++++++++++++++++++++++++++*/
   UTL_HTTP.set_proxy ('10.234.23.117:8080');
   /*+++++++++++++++++++++++++++++++*/
   /* in case it's needed set proxy */

   http_req := UTL_HTTP.begin_request (oauth_api_url, http_method, UTL_HTTP.http_version_1_1);
   UTL_HTTP.set_response_error_check (TRUE);
   UTL_HTTP.set_detailed_excp_support (TRUE);
   UTL_HTTP.set_body_charset (http_req, 'UTF-8');
   UTL_HTTP.set_header (http_req, 'User-Agent', 'Mozilla/4.0');
   UTL_HTTP.set_header (http_req, 'Authorization', http_post_data);
   UTL_HTTP.set_header (http_req, 'Content-Type', 'application/x-www-form-urlencoded');  
   UTL_HTTP.set_header (http_req, 'Content-Length', LENGTH(http_post_data)); 
   UTL_HTTP.write_text (http_req, http_post_data); 

   IF show_header = 1
   THEN
   DBMS_OUTPUT.put_line ('oauth_api_url='||oauth_api_url);
   DBMS_OUTPUT.put_line ('oauth_callback='||oauth_callback);
   DBMS_OUTPUT.put_line ('oauth_consumer_key='||oauth_consumer_key);
   DBMS_OUTPUT.put_line ('oauth_nonce='||oauth_nonce);
   DBMS_OUTPUT.put_line ('oauth_signature_method='||oauth_signature_method);
   DBMS_OUTPUT.put_line ('oauth_timestamp='||oauth_timestamp);
   DBMS_OUTPUT.put_line ('oauth_version='||oauth_version);
   DBMS_OUTPUT.put_line ('oauth_consumer_secret='||oauth_consumer_secret);
   DBMS_OUTPUT.put_line ('oauth_base_string='||oauth_base_string);
   DBMS_OUTPUT.put_line ('oauth_key:'||oauth_key);
   DBMS_OUTPUT.put_line ('oauth_signature='||oauth_signature);
   DBMS_OUTPUT.put_line ('l_sig_mac='||l_sig_mac);
   DBMS_OUTPUT.put_line ('http_post_data='||http_post_data);
   DBMS_OUTPUT.put_line ('http_method='||http_method);
   END IF;

   http_resp := UTL_HTTP.get_response (http_req);

   IF show_header = 1
   THEN
      DBMS_OUTPUT.put_line ('status code: ' || http_resp.status_code);
      DBMS_OUTPUT.put_line ('reason phrase: ' || http_resp.reason_phrase);
      FOR i IN 1 .. UTL_HTTP.get_header_count (http_resp)
      LOOP
         UTL_HTTP.get_header (http_resp, i, h_name, h_value);
         DBMS_OUTPUT.put_line (h_name || ': ' || h_value);
      END LOOP;
   END IF;

   IF show_xml = 1
   THEN
      BEGIN
         WHILE 1 = 1
         LOOP
            UTL_HTTP.read_line (http_resp, res_value, TRUE);
            DBMS_OUTPUT.put_line (res_value);
            --IF INSTR (res_value, 'oauth_token') > 0 THEN
            --  oauth_token := UTL_URL.UNESCAPE (SUBSTR (res_value, 13, instr(res_value, '&oauth_token_secre') - INSTR (res_value, 'oauth_token') - 12));
            --  oauth_token_secret := UTL_URL.UNESCAPE(SUBSTR (res_value, instr(res_value, '&oauth_token_secret') + 20));
            --  oauth_key := urlencode (oauth_consumer_secret) || '&' || urlencode (oauth_token_secret);
            --DBMS_OUTPUT.put_line ('oauth_token:'||oauth_token);
            --DBMS_OUTPUT.put_line ('oauth_token_secret:'||oauth_token_secret);
           --END IF;
         END LOOP;
      EXCEPTION
         WHEN UTL_HTTP.end_of_body
         THEN
            NULL;
      END;
   END IF;

   UTL_HTTP.end_response (http_resp);
  
EXCEPTION
   WHEN OTHERS
   THEN
      DBMS_OUTPUT.put_line (SQLERRM);
      RAISE;
   
END;
/

DROP FUNCTION urlencode;
DROP SEQUENCE oauth_nonce_seq;
