use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::process::Command;

#[cfg(target_os = "windows")]
fn install_certificate_windows(cert_path: &Path) -> Result<()> {
    let cert_path = cert_path
        .canonicalize()
        .with_context(|| format!("Failed to access certificate at {}", cert_path.display()))?;

    let mut path_str = cert_path.to_string_lossy().to_string();
    path_str = path_str.replace('\'', "''");

    let script = format!(
        "$p = Start-Process -FilePath certutil.exe -ArgumentList @('-addstore','-f','Root','{}') -Verb RunAs -PassThru -Wait; exit $p.ExitCode",
        path_str
    );

    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &script])
        .status()
        .context("Failed to launch PowerShell to install certificate")?;

    if !status.success() {
        let code = status.code().unwrap_or(-1);
        if code == 1223 {
            return Err(anyhow!(
                "Certificate installation was cancelled. Approval from the UAC prompt is required."
            ));
        }
        return Err(anyhow!(
            "certutil.exe returned a non-zero status (exit code {})",
            code
        ));
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn install_certificate_macos(cert_path: &Path) -> Result<()> {
    let cert_path = cert_path
        .canonicalize()
        .with_context(|| format!("Failed to access certificate at {}", cert_path.display()))?;
    let cert_str = cert_path.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"");

    let script = format!(
        "do shell script \"security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain \" & quoted form of \"{}\" with administrator privileges",
        cert_str
    );

    let status = Command::new("osascript")
        .arg("-e")
        .arg(script)
        .status()
        .context("Failed to launch osascript to install certificate")?;

    if !status.success() {
        return Err(anyhow!(
            "Failed to import certificate into the system keychain (osascript exit code {:?})",
            status.code()
        ));
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn install_certificate_linux(cert_path: &Path) -> Result<()> {
    let cert_path = cert_path
        .canonicalize()
        .with_context(|| format!("Failed to access certificate at {}", cert_path.display()))?;
    let cert_str = cert_path.to_string_lossy().replace('"', "\\\"");

    let script = format!(
        "set -e; CERT=\"{}\"; DEST=\"/usr/local/share/ca-certificates/maxproxy-selfsigned.crt\"; \
         install -Dm644 \"$CERT\" \"$DEST\"; \
         if command -v update-ca-certificates >/dev/null 2>&1; then \
             update-ca-certificates; \
         elif command -v trust >/dev/null 2>&1; then \
             trust anchor \"$DEST\"; \
         else \
             echo 'Neither update-ca-certificates nor trust command is available.' >&2; \
             exit 1; \
         fi",
        cert_str
    );

    let pkexec_status = Command::new("pkexec")
        .arg("bash")
        .arg("-c")
        .arg(&script)
        .status();

    match pkexec_status {
        Ok(status) if status.success() => Ok(()),
        Ok(status) => Err(anyhow!(
            "pkexec failed with exit code {:?}. Please ensure you approved the prompt.",
            status.code()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(anyhow!(
            "pkexec was not found. Please install the certificate manually using your distribution's tools."
        )),
        Err(e) => Err(anyhow!("Failed to execute pkexec: {}. Please ensure you have the necessary permissions to install certificates.", e)),
    }
}

#[cfg(not(target_os = "windows"))]
fn install_certificate_windows(_cert_path: &Path) -> Result<()> {
    Err(anyhow!(
        "Automatic certificate installation is only implemented for Windows, macOS, and Linux. Please install the certificate manually on your platform."
    ))
}

#[cfg(not(target_os = "macos"))]
fn install_certificate_macos(_cert_path: &Path) -> Result<()> {
    Err(anyhow!(
        "Automatic certificate installation is only implemented for Windows, macOS, and Linux. Please install the certificate manually on your platform."
    ))
}

#[cfg(not(target_os = "linux"))]
fn install_certificate_linux(_cert_path: &Path) -> Result<()> {
    Err(anyhow!(
        "Automatic certificate installation is only implemented for Windows, macOS, and Linux. Please install the certificate manually on your platform."
    ))
}

pub fn install_certificate(cert_path: &Path) -> Result<()> {
    if cfg!(target_os = "windows") {
        install_certificate_windows(cert_path)
    } else if cfg!(target_os = "macos") {
        install_certificate_macos(cert_path)
    } else if cfg!(target_os = "linux") {
        install_certificate_linux(cert_path)
    } else {
        Err(anyhow!(
            "Automatic certificate installation is not supported on this platform"
        ))
    }
}
