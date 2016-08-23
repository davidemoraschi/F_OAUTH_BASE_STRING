/* Formatted on 2010/08/11 11:47 (Formatter Plus v4.8.8) */
DROP TABLE oauth_parameters;
CREATE TABLE oauth_parameters
(
oauth_get_request_token_url VARCHAR2 (1000),
oauth_authorize_url         VARCHAR2 (1000),
oauth_get_access_token_url  VARCHAR2 (1000),
oauth_consumer_key      VARCHAR2(100),
oauth_consumer_secret   VARCHAR2(100),
oauth_token             VARCHAR2 (500),
oauth_token_secret      VARCHAR2 (500),
oauth_verifier          VARCHAR2 (500),
oauth_access_token        VARCHAR2 (500),
oauth_access_token_secret VARCHAR2 (500)
);
INSERT INTO oauth_parameters
            (oauth_get_request_token_url, oauth_authorize_url
            ,oauth_get_access_token_url, oauth_consumer_key, oauth_consumer_secret)
     VALUES ('https://api.twitter.com/oauth/request_token', 'https://api.twitter.com/oauth/authorize'
            ,'https://api.twitter.com/oauth/access_token', '5HFrVcwi7Hp1KpEQc4gfZQ', 'FV3fn9H6ZR3yrgNjfmb21I6zF58KmZLydWq4jXHqhA');
COMMIT ;