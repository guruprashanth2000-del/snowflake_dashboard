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
---
    -- Exclude deleted users

------------------------VW_USER_LOGIN_DETAILS

    CREATE VIEW VW_USER_LOGIN_DETAILS AS 
SELECT
    USER_NAME,
    EVENT_TIMESTAMP LOGGED_ON_HIST,
    -- CLIENT_IP,
    -- AUTHENTICATION_METHOD,
    IS_SUCCESS
FROM
    SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
where
    event_timestamp > current_date -90;-- 

    -----------------VW_SNOW_DORMANT_USER

    CREATE VIEW VW_SNOW_DORMANT_USER
    AS
    SELECT
    NAME,
    LAST_SUCCESS_LOGIN,
    CREATED_ON
FROM
    SNOWFLAKE.ACCOUNT_USAGE.USERS
WHERE
    LAST_SUCCESS_LOGIN IS NULL AND CREATED_ON < DATEADD(DAY, -90, CURRENT_DATE()); ---VW_SNOW_DORMANT_USER


    CREATE VIEW VW_USER_CREDITS AS
    SELECT
    USER_NAME,
    WAREHOUSE_NAME,
    SUM(CREDITS_ATTRIBUTED_COMPUTE) AS TOTAL_CREDITS_ATTRIBUTED,
    COUNT(QUERY_ID) AS TOTAL_QUERIES
FROM
    SNOWFLAKE.ACCOUNT_USAGE.QUERY_ATTRIBUTION_HISTORY
WHERE
    START_TIME >= DATEADD(MONTH, -1, CURRENT_DATE()) -- For the last 1 month
GROUP BY
    USER_NAME, WAREHOUSE_NAME;--




    -------------VW_ROLE_HIERARCHY

    CREATE VIEW VW_ROLE_HIERARCHY AS 

    -- Step 1: Build the recursive hierarchy starting from a known root role

with recursive role_cte as (

    select 

        name,

        grantee_name

    from snowflake.account_usage.grants_to_roles

    where granted_on = 'ROLE'

      and privilege = 'USAGE'

      and deleted_on is null

      and grantee_name = 'ACCOUNTADMIN'  -- Replace with your root role

    union all

    select 

        gtr.name,

        gtr.grantee_name

    from snowflake.account_usage.grants_to_roles gtr

    join role_cte on gtr.grantee_name = role_cte.name

    where gtr.granted_on = 'ROLE'

      and gtr.privilege = 'USAGE'

      and gtr.deleted_on is null

)

-- Step 2: Assign IDs and Parent IDs using ROW_NUMBER and JOIN

, numbered_roles as (

    select 

        name,

        grantee_name,

        row_number() over (order by name) as id

    from role_cte

)

select 

    child.id as ID,

    parent.id as Parent_ID,

    child.name as Role_Name

from numbered_roles child

left join numbered_roles parent

    on child.grantee_name = parent.name

order by child.id;

-----------------VW_ROLE_METRICS

 CREATE VIEW VW_ROLE_METRICS AS 

WITH RoleHierarchy AS (

    -- Anchor member: Select all roles that are granted to other roles (potential parents)

    SELECT

        GRANTEE_NAME AS PARENT_ROLE,

        NAME AS CHILD_ROLE,

        1 AS HIERARCHY_LEVEL,

        ARRAY_CONSTRUCT(GRANTEE_NAME, NAME) AS ROLE_PATH -- Stores the full path

    FROM

        SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES

    WHERE

        GRANTED_ON = 'ROLE'

        AND PRIVILEGE = 'USAGE'

        AND DELETED_ON IS NULL
 
    UNION ALL
 
    -- Recursive member: Find grandparents, great-grandparents, etc.

    SELECT

        RH.PARENT_ROLE,

        gtr.NAME AS CHILD_ROLE,

        RH.HIERARCHY_LEVEL + 1 AS HIERARCHY_LEVEL,

        ARRAY_APPEND(RH.ROLE_PATH, gtr.NAME) AS ROLE_PATH

    FROM

        SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES gtr

    INNER JOIN

        RoleHierarchy RH ON gtr.GRANTEE_NAME = RH.CHILD_ROLE

    WHERE

        gtr.GRANTED_ON = 'ROLE'

        AND gtr.PRIVILEGE = 'USAGE'

        AND gtr.DELETED_ON IS NULL

),

-- Flatten the hierarchy paths to show all roles involved up to level 10

FlattenedHierarchy AS (

    SELECT

        PARENT_ROLE,

        CHILD_ROLE,

        HIERARCHY_LEVEL,

        ROLE_PATH,

        GET(ROLE_PATH, 0)::VARCHAR AS HIERARCHY_LEVEL_1_ROLE, -- Main Parent

        GET(ROLE_PATH, 1)::VARCHAR AS HIERARCHY_LEVEL_2_ROLE,

        GET(ROLE_PATH, 2)::VARCHAR AS HIERARCHY_LEVEL_3_ROLE,

        GET(ROLE_PATH, 3)::VARCHAR AS HIERARCHY_LEVEL_4_ROLE,

        GET(ROLE_PATH, 4)::VARCHAR AS HIERARCHY_LEVEL_5_ROLE,

        GET(ROLE_PATH, 5)::VARCHAR AS HIERARCHY_LEVEL_6_ROLE,

        GET(ROLE_PATH, 6)::VARCHAR AS HIERARCHY_LEVEL_7_ROLE,

        GET(ROLE_PATH, 7)::VARCHAR AS HIERARCHY_LEVEL_8_ROLE,

        GET(ROLE_PATH, 8)::VARCHAR AS HIERARCHY_LEVEL_9_ROLE,

        GET(ROLE_PATH, 9)::VARCHAR AS HIERARCHY_LEVEL_10_ROLE

    FROM RoleHierarchy

),

-- All roles involved in the hierarchy, including parents themselves

AllRolesInHierarchy AS (

    SELECT PARENT_ROLE AS ROLE_NAME FROM RoleHierarchy

    UNION

    SELECT CHILD_ROLE FROM RoleHierarchy

),

-- Add top-level roles that might not be granted to other roles but still have privileges

TopLevelRoles AS (

    SELECT DISTINCT GRANTEE_NAME AS ROLE_NAME

    FROM SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES

    WHERE GRANTED_TO = 'ROLE' AND DELETED_ON IS NULL

    EXCEPT

    SELECT CHILD_ROLE FROM RoleHierarchy -- Exclude roles that are already children in some hierarchy

),

-- Combine all unique roles we care about

RelevantRoles AS (

    SELECT ROLE_NAME FROM AllRolesInHierarchy

    UNION

    SELECT ROLE_NAME FROM TopLevelRoles

    WHERE ROLE_NAME NOT IN ('PUBLIC')

),

DirectPrivilegesRaw AS (

    SELECT

        GRANTS.GRANTEE_NAME AS ROLE_NAME,

        GRANTS.TABLE_CATALOG AS DATABASE_NAME,

        GRANTS.TABLE_SCHEMA AS SCHEMA_NAME,

        CASE

            WHEN GRANTS.PRIVILEGE IN ('INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'OWNERSHIP', 'REBUILD', 'APPLYBUDGET', 'EVOLVE SCHEMA') THEN 'RW'

            WHEN GRANTS.PRIVILEGE = 'SELECT' THEN 'RO'

            ELSE 'OTHER'

        END AS PRIVILEGE_CATEGORY

    FROM

        SNOWFLAKE.ACCOUNT_USAGE.GRANTS_TO_ROLES AS GRANTS

    WHERE

        GRANTS.GRANTED_ON IN ('TABLE', 'VIEW')

        AND GRANTS.DELETED_ON IS NULL

        AND GRANTS.GRANTEE_NAME IN (SELECT ROLE_NAME FROM RelevantRoles)

),

DirectPrivileges AS (

    SELECT

        ROLE_NAME,

        DATABASE_NAME,

        SCHEMA_NAME,

        PRIVILEGE_CATEGORY

    FROM

        DirectPrivilegesRaw

    QUALIFY ROW_NUMBER() OVER (

        PARTITION BY ROLE_NAME, DATABASE_NAME, SCHEMA_NAME

        ORDER BY

            CASE PRIVILEGE_CATEGORY

                WHEN 'RW' THEN 1

                WHEN 'RO' THEN 2

                WHEN 'OTHER' THEN 3

                ELSE 4

            END ASC

    ) = 1

),

-- Final result set before the new prioritization

FinalResultSetBeforePrioritization AS (

    SELECT DISTINCT

        COALESCE(FH.HIERARCHY_LEVEL_1_ROLE, DP.ROLE_NAME) AS TOP_LEVEL_PARENT_ROLE,

        FH.HIERARCHY_LEVEL_2_ROLE,

        FH.HIERARCHY_LEVEL_3_ROLE,

        FH.HIERARCHY_LEVEL_4_ROLE,

        FH.HIERARCHY_LEVEL_5_ROLE,

        FH.HIERARCHY_LEVEL_6_ROLE,

        FH.HIERARCHY_LEVEL_7_ROLE,

        FH.HIERARCHY_LEVEL_8_ROLE,

        FH.HIERARCHY_LEVEL_9_ROLE,

        FH.HIERARCHY_LEVEL_10_ROLE,

        DP.ROLE_NAME AS ROLE_WITH_DIRECT_PRIVILEGE,

        DP.DATABASE_NAME,

        DP.SCHEMA_NAME,

        DP.PRIVILEGE_CATEGORY

    FROM

        DirectPrivileges DP

    LEFT JOIN

        FlattenedHierarchy FH ON DP.ROLE_NAME = FH.CHILD_ROLE

    WHERE

        DP.ROLE_NAME IN (SELECT ROLE_NAME FROM RelevantRoles)

)

SELECT

    TOP_LEVEL_PARENT_ROLE,

  /*  HIERARCHY_LEVEL_2_ROLE,

    HIERARCHY_LEVEL_3_ROLE,

    HIERARCHY_LEVEL_4_ROLE,

    HIERARCHY_LEVEL_5_ROLE,

    HIERARCHY_LEVEL_6_ROLE,

    HIERARCHY_LEVEL_7_ROLE,

    HIERARCHY_LEVEL_8_ROLE,

    HIERARCHY_LEVEL_9_ROLE,

    HIERARCHY_LEVEL_10_ROLE,

    ROLE_WITH_DIRECT_PRIVILEGE, */

    DATABASE_NAME, 

    SCHEMA_NAME,

    PRIVILEGE_CATEGORY

FROM

    FinalResultSetBeforePrioritization

QUALIFY ROW_NUMBER() OVER (

    PARTITION BY TOP_LEVEL_PARENT_ROLE, DATABASE_NAME, SCHEMA_NAME

    ORDER BY

        CASE PRIVILEGE_CATEGORY

            WHEN 'RW' THEN 1

            WHEN 'RO' THEN 2

            WHEN 'OTHER' THEN 3

            ELSE 4

        END ASC

) = 1

ORDER BY

    TOP_LEVEL_PARENT_ROLE, HIERARCHY_LEVEL_2_ROLE, HIERARCHY_LEVEL_3_ROLE, HIERARCHY_LEVEL_4_ROLE, HIERARCHY_LEVEL_5_ROLE,

    HIERARCHY_LEVEL_6_ROLE, HIERARCHY_LEVEL_7_ROLE, HIERARCHY_LEVEL_8_ROLE, HIERARCHY_LEVEL_9_ROLE, HIERARCHY_LEVEL_10_ROLE,

    ROLE_WITH_DIRECT_PRIVILEGE, DATABASE_NAME, SCHEMA_NAME, PRIVILEGE_CATEGORY;

 