#[tokio::main]
async fn main() {
    let client = OAuth2Client {
        client_id: "xxx".into(),
        client_secret: "yyy".into(),
        auth_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
        token_url: "https://oauth2.googleapis.com/token".into(),
        redirect_uri: "https://myapp.com/callback".into(),
    };

    // 1. build login URL
    let url = client.authorization_url(
        "openid email profile",
        "random_state_123",
        None,
    );

    println!("Login URL: {}", url);

    // 2. callback reçu du provider
    let callback_url = "https://myapp.com/callback?code=ABC123&state=random_state_123";

    let callback = OAuth2Callback::from_url(callback_url).unwrap();

    // 3. exchange token
    let token = client.exchange_code(&callback.code).await.unwrap();

    println!("access_token = {}", token.access_token);
}