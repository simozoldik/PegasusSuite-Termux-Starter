# Pegasus Suite — updates from Termux, builds in GitHub Actions

This package is a **working source starting point**, not a claim that the recovered app is byte-identical to the prior Windows build. The recovered ZIP differs from the existing APK in `app.js`, `index.html`, and `styles.css`. It does preserve the PHONES tab, `ps-hack`, the native CellTower/PhoneScanner/WiFi scan plugins, and the backend/frontend source collected in `pegasus_discovery_review.zip`.

The Android folder in the recovered archive is incomplete (no `settings.gradle`, Gradle wrapper, and some resources). The workflow regenerates a clean Capacitor Android scaffold on the GitHub runner, then restores the recovered Gradle configuration and custom Java plugins. It does **not** modify the checked-in Android directory on your phone.

## The update path

1. Edit `frontend/app.js`, `frontend/index.html`, `frontend/styles.css`, or Java files under `native-plugins/java/` in Termux.
2. Run the web checks and push the changes to your private GitHub repo.
3. GitHub Actions builds a newly signed APK in the cloud.
4. Download the APK from the workflow run's **Artifacts** section on your phone and install it over the prior CI-signed build.

## Important limitations

- This is a recovery baseline, not the exact old Windows source. Its frontend files do not byte-match the APK that was uploaded previously.
- The prior Windows backend URL was a private-LAN address. It is not assumed to work now. `frontend/config.js` starts with an empty API URL. Until a reachable backend is deployed/configured, backend-dependent features may fail; the APK build itself does not deploy the backend.
- The collected backend has Windows-specific local-network discovery assumptions. Do not assume it runs correctly under Termux or a Linux server without testing/porting those functions.
- The recovered `network_security_config.xml` is explicitly labelled INTERNAL TEST and permits cleartext traffic broadly. Do not publish this build as a production app without hardening the network policy and using HTTPS.
- Developer Mode / `SettingsNavPlugin` and the newer OSINT dropdown are **not** included in this starting package. Add them only after the build pipeline is proven.
- The first APK signed with your new key may not install over the old Windows-built APK if their signing certificates differ. Keep a copy of the old APK. A one-time uninstall/reinstall may be required and can erase that app's local data. After the first install from this CI workflow, reuse the same signing key forever for in-place updates.

## A. Extract on Samsung Galaxy A54

Download this ZIP to Android's Downloads folder, then in Termux:

```bash
termux-setup-storage
pkg update
pkg install git nodejs-lts unzip openssh
mkdir -p ~/projects
unzip ~/storage/shared/Download/PegasusSuite-Termux-Starter.zip -d ~/projects/
cd ~/projects/PegasusSuite-Termux-Starter
npm run build
npm run test:web
```

If your downloaded ZIP has a different filename, replace it in the `unzip` command. Do not move or delete your old APK.

## B. Create the stable signing key once

Install Java/keytool in Termux if it is not already available (`pkg search openjdk` to see available versions):

```bash
pkg install openjdk-17
mkdir -p ~/.keys/pegasus
chmod 700 ~/.keys/pegasus
keytool -genkeypair -v -keystore ~/.keys/pegasus/pegasus-release.jks -storetype JKS -alias pegasus -keyalg RSA -keysize 2048 -validity 10000
```

Choose a strong keystore password and key password; keep them private. Do not commit the `.jks` file or send it in chat. Copy the base64 output to a GitHub secret without line breaks:

```bash
base64 ~/.keys/pegasus/pegasus-release.jks | tr -d '\n'
```

Create a **private** GitHub repository in the phone browser. Under **Settings → Secrets and variables → Actions → New repository secret**, add:

- `PEGASUS_KEYSTORE_BASE64` — the base64 text from the command above
- `PEGASUS_STORE_PASSWORD` — the keystore password
- `PEGASUS_KEY_ALIAS` — `pegasus`
- `PEGASUS_KEY_PASSWORD` — the key password

Never paste the private key or its passwords into a chat or commit them to the repository. If `openjdk-17` is not available in your Termux repository, install an available OpenJDK package that includes `keytool`; the build itself uses Java 17 on GitHub's runner.

## C. Push the project to GitHub

Create an **empty private repository** in the GitHub browser (do not initialize it with a README). Then run the following in the project folder, replacing `YOUR_USERNAME` and `YOUR_REPO`:

```bash
git init -b main
git config user.name "Pegasus Developer"
git config user.email "YOUR_GITHUB_EMAIL"
git add .
git commit -m "Set up Pegasus Suite phone-based build"
git remote add origin git@github.com:YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

For SSH authentication, create a key with `ssh-keygen -t ed25519 -C "pegasus-termux"`, add the contents of `~/.ssh/id_ed25519.pub` under GitHub **Settings → SSH and GPG keys**, and verify with `ssh -T git@github.com`. Keep the private file `~/.ssh/id_ed25519` private.

## D. Every future update from Termux

```bash
cd ~/projects/PegasusSuite-Termux-Starter
nano frontend/app.js       # or the file you need to change
npm run build
npm run test:web
git add .
git commit -m "Describe the change"
git push
```

After GitHub Actions finishes, open the repository → **Actions** → latest **Build Pegasus Suite APK** run → **Artifacts** → download `Pegasus-Suite-release-...`. Extract the downloaded artifact ZIP to get the APK. Because every build uses the same signing key and increments `versionCode`, it can update a prior install from this workflow without uninstalling (provided the app ID stays `com.pegasus.suite`).

## Optional backend URL

If you later host a backend at a reachable HTTPS address, add a GitHub **repository variable** named `PEGASUS_API_BASE_URL` with that base URL (no trailing slash). The workflow passes it into `scripts/build-web.js`. The backend is not deployed by this APK workflow.
