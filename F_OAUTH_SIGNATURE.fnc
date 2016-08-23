/* Formatted on 2010/08/10 15:50 (Formatter Plus v4.8.8) */
CREATE OR REPLACE FUNCTION f_oauth_signature (p_oauth_base_string IN VARCHAR2, p_oauth_key IN VARCHAR2)
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
END;
/