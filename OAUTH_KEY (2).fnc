/* Formatted on 2010/08/10 15:15 (Formatter Plus v4.8.8) */
CREATE OR REPLACE FUNCTION oauth_key
   RETURN VARCHAR2
AS
   v_oauth_key                   VARCHAR2 (500);
BEGIN
   SELECT urlencode ('7XF7YN/rNzYcqDlJFsTqyC81KWw=') || '&'
   INTO   v_oauth_key
   FROM   DUAL;

   RETURN v_oauth_key;
END;