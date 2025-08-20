-----------------------VW_SNOW_USER_TABLE

CREATE VIEW VW_SNOW_USER_TABLE AS
SELECT
    NAME AS "User",
    DISPLAY_NAME AS "Display Name",
    LAST_SUCCESS_LOGIN AS "Last Login",
    HAS_MFA AS "MFA Status",
    DISABLED AS "User Status",
    DEFAULT_WAREHOUSE AS "DEFAULT_WAREHOUSE",
    CREATED_ON AS "Creation Date"
FROM
    SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE
    DELETED_ON IS NULL;


    git config --global user.name "guruprashanth2000-del"
 
git config --global user.email guruprashanth2000@gmail.com
 
 