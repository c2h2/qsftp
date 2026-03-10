use anyhow::Result;

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
}

/// Authenticate using PAM (same as sshd), then get user info from /etc/passwd.
pub fn authenticate_pam(username: &str, password: &str) -> Result<UserInfo> {
    let mut client = pam::Client::with_password("qsftp")
        .map_err(|e| anyhow::anyhow!("PAM init failed: {}", e))?;
    client
        .conversation_mut()
        .set_credentials(username, password);
    client
        .authenticate()
        .map_err(|e| anyhow::anyhow!("PAM auth failed: {}", e))?;
    client
        .open_session()
        .map_err(|e| anyhow::anyhow!("PAM session failed: {}", e))?;

    get_user_info(username)
}

/// Shadow-based authentication fallback (needs root)
pub fn authenticate_shadow(username: &str, password: &str) -> Result<UserInfo> {
    // Try PAM first
    match authenticate_pam(username, password) {
        Ok(info) => return Ok(info),
        Err(e) => {
            tracing::warn!("PAM auth failed: {}", e);
        }
    }

    // Fallback: python shadow check (requires root)
    if verify_unix_password(username, password)? {
        get_user_info(username)
    } else {
        anyhow::bail!("authentication failed for user {}", username)
    }
}

pub fn get_user_info_public(username: &str) -> Result<UserInfo> {
    get_user_info(username)
}

fn get_user_info(username: &str) -> Result<UserInfo> {
    use std::process::Command;

    let output = Command::new("id").args(["-u", username]).output()?;
    if !output.status.success() {
        anyhow::bail!("user '{}' not found", username);
    }
    let uid: u32 = String::from_utf8(output.stdout)?.trim().parse()?;

    let output = Command::new("id").args(["-g", username]).output()?;
    let gid: u32 = String::from_utf8(output.stdout)?.trim().parse()?;

    // Get home directory from getent
    let output = Command::new("getent")
        .args(["passwd", username])
        .output()?;
    let passwd_line = String::from_utf8(output.stdout)?;
    let home = passwd_line
        .trim()
        .split(':')
        .nth(5)
        .unwrap_or("/tmp")
        .to_string();

    Ok(UserInfo {
        username: username.to_string(),
        uid,
        gid,
        home,
    })
}

fn verify_unix_password(username: &str, password: &str) -> Result<bool> {
    use std::process::Command;

    let script = format!(
        r#"
import crypt, spwd
try:
    sp = spwd.getspnam('{}')
    result = crypt.crypt('{}', sp.sp_pwdp)
    print('OK' if result == sp.sp_pwdp else 'FAIL')
except Exception as e:
    print(f'ERR:{{e}}')
"#,
        username.replace('\'', ""),
        password.replace('\'', "")
    );

    let output = Command::new("python3").args(["-c", &script]).output()?;
    let result = String::from_utf8(output.stdout)?.trim().to_string();
    Ok(result == "OK")
}
