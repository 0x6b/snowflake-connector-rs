use snowflake_connector_rs::{Result, SnowflakeAuthMethod, SnowflakeClient, SnowflakeClientConfig};

#[tokio::main]
async fn main() -> Result<()> {
    let username = std::env::var("SNOWFLAKE_USERNAME").expect("set SNOWFLAKE_USERNAME");
    let account = std::env::var("SNOWFLAKE_ACCOUNT").expect("set SNOWFLAKE_ACCOUNT");

    let role = std::env::var("SNOWFLAKE_ROLE").ok();
    let warehouse = std::env::var("SNOWFLAKE_WAREHOUSE").ok();
    let database = std::env::var("SNOWFLAKE_DATABASE").ok();
    let schema = std::env::var("SNOWFLAKE_SCHEMA").ok();

    println!("Creating client with external browser authentication...");
    println!("Account: {account}");
    println!("Username: {username}");

    let client = SnowflakeClient::new(
        &username,
        SnowflakeAuthMethod::ExternalBrowser,
        SnowflakeClientConfig {
            account,
            warehouse,
            database,
            schema,
            role,
            timeout: None,
        },
    )?;

    println!("Creating session...");
    println!("A browser window should open for authentication.");

    match client.create_session().await {
        Ok(session) => {
            println!("Session created successfully!");

            // Try a simple query
            let rows = session.query("SELECT CURRENT_USER()").await?;
            println!(
                "Current user: {:?}",
                rows[0].get::<String>("CURRENT_USER()")?
            );

            Ok(())
        }
        Err(e) => {
            eprintln!("Failed to create session: {e:?}");
            Err(e)
        }
    }
}
