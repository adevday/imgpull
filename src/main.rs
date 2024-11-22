use std::borrow::Cow;
use std::env::temp_dir;
use std::error::Error;
use std::fs::File;
use std::sync::Arc;



use argh::FromArgs;
use kdam::{tqdm, BarExt};
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, stdout, Write};
use std::path::Path;
use std::process::exit;

use std::{fs, str};
use ureq::Agent;
type Result<T> = std::result::Result<T, Box<dyn Error>>;

static AGENT: Lazy<Agent> = Lazy::new(|| {
    ureq::AgentBuilder::new()
        .tls_connector(Arc::new(native_tls::TlsConnector::new().unwrap()))
        .try_proxy_from_env(true)
        .build()
});

#[derive(FromArgs, Debug)]
#[argh(example = "
# Download a single image and save as a tar file
imgpull nginx:latest --out ./nginx_latest.tar

# Download multiple images
imgpull nginx:latest postgres:12 --arch arm64

# Download and load the image into Docker
imgpull ghcr.io/linuxserver/nginx:latest --out - | docker load")]
/// Download Docker images and save them as tar files (loadable via `docker load`).
struct Args {
    /// target architecture for the image
    #[argh(
        option,
        default = "String::from(map_rust_arch_to_goarch(std::env::consts::ARCH))"
    )]
    arch: String,

    /// registry to use for the download
    #[argh(option, default = "String::from(\"https://registry-1.docker.io\")")]
    registry: String,

    /// temporary directory for layer downloading
    #[argh(option)]
    tmp: Option<String>,

    /// output file path to save the tar file
    #[argh(option)]
    out: Option<String>,

    /// list of images to download (e.g., NAME:TAG).
    #[argh(positional)]
    images: Vec<String>,
}

fn map_rust_arch_to_goarch(rust_arch: &str) -> &'static str {
    match rust_arch {
        "x86" => "386",
        "x86_64" => "amd64",
        "arm" => "arm",
        "aarch64" => "arm64",
        "mips" => "mips",
        "mips64" => "mips64",
        "powerpc" => "ppc",
        "powerpc64" => "ppc64",
        "s390x" => "s390x",
        "riscv64" => "riscv64",
        "sparc64" => "sparc64",
        "wasm32" => "wasm",
        _ => "unknown",
    }
}

#[derive(Debug, Default)]
pub struct Image {
    pub registry: Option<String>,
    pub namespace: String,
    pub name: String,
    pub tag: String,
    pub digest: Option<String>,
}

impl Image {
    pub fn registry_url<'a, 'b: 'a>(&'a self, fallback: &'b str) -> Cow<'a, str> {
        if let Some(reg) = self.registry.as_ref() {
            format!("https://{}", reg).into()
        } else {
            fallback.into()
        }
    }
    pub fn to_string(&self) -> String {
        format!("{}:{}", self.image_name(), self.tag)
    }

    pub fn image_name(&self) -> String {
        let mut out = String::new();
        if let Some(registry) = &self.registry {
            out.push_str(&format!("{}/", registry));
        }
        if self.namespace != "library" {
            out.push_str(&format!("{}/", self.namespace));
        }
        out.push_str(&self.name);
        out
    }

    pub fn auth_server(&self, registry: &str) -> Result<Option<(String, String)>> {
        let resp = AGENT
            .get(&format!("{}/v2/", self.registry_url(registry)))
            .call();

        if resp.is_ok() {
            return Ok(None);
        }
        let resp = resp.unwrap_err().into_response().unwrap();

        if resp.status() / 100 == 4 {
            if let Some(wwwauth) = resp.header("www-authenticate") {
                let wwwauth = wwwauth.trim();
                const BEARER_PREFIX: &str = "Bearer ";
                const SERVICE_PREFIX: &str = "service=\"";
                const REALM_PREFIX: &str = "realm=\"";

                if !wwwauth.starts_with(BEARER_PREFIX) {
                    return Err(format!("unknown www-authenticate {}", wwwauth).into());
                }

                let mut realm = String::new();
                let mut service = String::new();
                for kv in wwwauth[BEARER_PREFIX.len()..].split(&[';', ',']) {
                    if kv.starts_with(SERVICE_PREFIX) {
                        service = kv[SERVICE_PREFIX.len()..kv.len() - 1].to_string();
                    }
                    if kv.starts_with(REALM_PREFIX) {
                        realm = kv[REALM_PREFIX.len()..kv.len() - 1].to_string();
                    }
                }

                return Ok(Some((realm, service)));
            }
        }
        Ok(None)
    }
}

pub fn parse_image_name(image: &str) -> Image {
    let mut ref_image = Image::default();

    let parts: Vec<&str> = image.splitn(3, '/').collect();
    match parts.len() {
        1 => {
            ref_image.namespace = "library".to_string();
            ref_image.name = parts[0].to_string();
        }
        2 => {
            if parts[0] == "_" {
                ref_image.namespace = "library".to_string();
                ref_image.name = parts[1].to_string();
            } else {
                ref_image.namespace = parts[0].to_string();
                ref_image.name = parts[1].to_string();
            }
        }
        3 => {
            ref_image.registry = if parts[0] != "_" {
                Some(parts[0].to_string())
            } else {
                None
            };
            ref_image.namespace = parts[1].to_string();
            ref_image.name = parts[2].to_string();
        }
        _ => {}
    }
    let mut image_name = ref_image.name.clone();
    let name_parts: Vec<&str> = image_name.splitn(2, '@').collect();
    if name_parts.len() == 2 {
        ref_image.name = name_parts[0].to_string();
        ref_image.digest = Some(name_parts[1].to_string());
    }
    image_name = ref_image.name.clone();
    let name_parts: Vec<&str> = image_name.splitn(2, ':').collect();
    if name_parts.len() == 2 {
        ref_image.name = name_parts[0].to_string();
        ref_image.tag = name_parts[1].to_string();
    }

    if ref_image.tag.is_empty() {
        ref_image.tag = "latest".to_string();
    }

    ref_image
}

use serde_json::{json, Value};

fn get_token(realm: &str, service: &str, image: &Image) -> Result<String> {
    let url = format!(
        "{}?service={}&scope=repository:{}/{}:pull",
        realm, service, image.namespace, image.name
    );
    let resp = AGENT.get(&url).call()?;
    let result: HashMap<String, Value> = resp.into_json()?;
    if let Some(token) = result.get("token").and_then(Value::as_str) {
        Ok(token.to_string())
    } else {
        Err("error: failed to parse token response".into())
    }
}

fn get_manifest(
    registry: &str,
    image: &Image,
    token: Option<&str>,
    reference: Option<&str>,
) -> Result<Value> {
    let reference = reference.unwrap_or(&image.tag);
    let registry = image.registry_url(registry);

    let url = format!(
        "{}/v2/{}/{}/manifests/{}",
        registry, image.namespace, image.name, reference
    );

    let mut builder = AGENT
        .get(&url)
        .set("Accept", "application/vnd.oci.image.manifest.v1+json")
        .set("Accept", "application/vnd.oci.image.index.v1+json")
        .set(
            "Accept",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
        .set(
            "Accept",
            "application/vnd.docker.distribution.manifest.list.v2+json",
        )
        .set(
            "Accept",
            "application/vnd.docker.distribution.manifest.v1+json",
        );

    if let Some(token) = token {
        builder = builder.set("Authorization", &format!("Bearer {}", token));
    }

    Ok(builder.call()?.into_json()?)
}

fn fetch_blob(
    registry: &str,
    image: &Image,
    token: Option<&str>,
    digest: &str,
    target_file: &Path,
) -> Result<()> {
    eprintln!("fetching blob: {}", &digest[8..24]);
    let url = format!(
        "{}/v2/{}/{}/blobs/{}",
        image.registry_url(registry),
        image.namespace,
        image.name,
        digest
    );

    let mut builder = AGENT.get(&url);

    if let Some(token) = token {
        builder = builder.set("Authorization", &format!("Bearer {}", token));
    }

    let resp = builder.call()?;
    let mut buf = vec![0_u8; 1024];
    let total = resp
        .header("content-length")
        .and_then(|x| x.parse::<i32>().ok())
        .unwrap_or(0);
    let mut pb = tqdm!(
        total = total as usize,
        unit_scale = true,
        unit_divisor = 1024,
        unit = "B",
        force_refresh = true
    );

    let mut rdr = resp.into_reader();
    let mut dst = File::create(target_file)?;
    loop {
        let n = rdr.read(&mut buf)?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[0..n])?;
        pb.update(n)?;
    }

    Ok(())
}

pub fn handle_single_manifest_v2(
    registry: &str,
    image: &Image,
    manifest_json: Value,
    token: Option<&str>,
    dir: &str,
) -> Result<(Value, String)> {
    let config_digest = manifest_json["config"]["digest"].as_str().unwrap();
    let image_id = config_digest.trim_start_matches("sha256:");
    let config_file = format!("{}.json", image_id);
    let mut layer_id = Cow::Borrowed("");
    let mut layer_json = Value::default();
    let mut layer_files: Vec<String> = Vec::new();

    fetch_blob(
        registry,
        &image,
        token,
        config_digest,
        &Path::new(dir).join(&config_file),
    )?;

    let layers = manifest_json["layers"].as_array().unwrap();

    for layer in layers {
        let layer_meta = layer.as_object().unwrap();
        let layer_media_type = layer_meta["mediaType"].as_str().unwrap();
        let layer_digest = layer_meta["digest"].as_str().unwrap();
        let parent_id = layer_id.to_string();
        let mut hasher = Sha256::new();
        hasher.update(format!("{}\n{}", layer_id, layer_digest));
        layer_id = format!("{:x}", hasher.finalize()).into();

        let layer_dir = Path::new(dir).join(layer_id.as_ref());
        fs::create_dir_all(&layer_dir)?;
        fs::write(layer_dir.join("VERSION"), "1.0")?;

        let layer_tar = format!("{}/layer.tar", layer_id);
        layer_files.push(layer_tar.clone());

        layer_json = json!({
            "id": layer_id,
            "created": "0001-01-01T00:00:00Z",
            "container_config": {
                "Hostname": "",
                "Domainname": "",
                "User": "",
                "AttachStdin": false,
                "AttachStdout": false,
                "AttachStderr": false,
                "Tty": false,
                "OpenStdin": false,
                "StdinOnce": false,
                "Env": Value::Null,
                "Cmd": Value::Null,
                "Image": "",
                "Volumes": Value::Null,
                "WorkingDir": "",
                "Entrypoint": Value::Null,
                "OnBuild": Value::Null,
                "Labels": Value::Null,
            }
        });
        if !parent_id.is_empty() {
            layer_json
                .as_object_mut()
                .unwrap()
                .insert("parentId".to_string(), json!(parent_id));
        }
        let data = serde_json::to_string(&layer_json)?;
        fs::write(layer_dir.join("json"), data)?;

        match layer_media_type {
            "application/vnd.oci.image.layer.v1.tar+gzip"
            | "application/vnd.docker.image.rootfs.diff.tar.gzip" => {
                fetch_blob(
                    registry,
                    &image,
                    token,
                    layer_digest,
                    &Path::new(dir).join(&layer_tar),
                )?;
            }
            _ => {
                return Err(Box::new(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "error: unknown media type ({}, {}): '{}'",
                        image.name, layer_media_type, layer_id
                    ),
                )));
            }
        }
    }

    let config_file_bytes = fs::read(Path::new(dir).join(&config_file))?;
    let mut config_json: HashMap<String, Value> = serde_json::from_slice(&config_file_bytes)?;
    config_json.insert("id".to_string(), json!(layer_json["id"].as_str().unwrap()));
    if let Some(parent_id) = layer_json.get("parentId").and_then(|v| v.as_str()) {
        if !parent_id.is_empty() {
            config_json.insert("parentId".to_string(), json!(parent_id));
        }
    }
    config_json.remove("history");
    config_json.remove("rootfs");
    let data = serde_json::to_string(&config_json)?;
    fs::write(Path::new(dir).join(layer_id.as_ref()).join("json"), data)?;

    let manifest = json!({
        "Config": config_file,
        "RepoTags": [image.to_string()],
        "Layers": layer_files,
    });

    Ok((manifest, layer_id.to_string()))
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();

    if args.images.is_empty() {
        eprintln!("Error: 'image' is a required positional argument");
        exit(1);
    }
    eprintln!(
        "imgpull {} | (https://github.com/adevday/imgpull)\n",
        option_env!("BUILD_VERSION").unwrap_or("dev-build")
    );
    let images = args
        .images
        .into_iter()
        .map(|x| parse_image_name(&x))
        .collect::<Vec<_>>();

    let mut out_name = args
        .out
        .clone()
        .unwrap_or_else(|| images[0].image_name().replace("/", "_"));

    let download_dir = Path::new(
        &args
            .tmp
            .clone()
            .unwrap_or_else(|| temp_dir().to_string_lossy().to_string()),
    )
    .join(format!("{}_content", out_name))
    .to_string_lossy()
    .to_string();
    fs::create_dir_all(&download_dir)?;
    if !out_name.ends_with(".tar") {
        out_name += ".tar";
    }

    let mut manifest_out: Vec<Value> = Vec::new();
    let mut repositories: HashMap<String, HashMap<String, String>> = HashMap::new();

    for image in images {
        let token = image
            .auth_server(&args.registry)?
            .map(|(realm, service)| get_token(&realm, &service, &image))
            .transpose()?;

        let token_ref = token.as_ref().map(|x| x.as_str());
        let manifest = get_manifest(&args.registry, &image, token_ref, None)?;

        let schema_version = manifest["schemaVersion"]
            .as_u64()
            .ok_or("error: schemaVersion is not a valid number")?
            as usize;

        match schema_version {
            2 => {
                let media_type = manifest["mediaType"]
                    .as_str()
                    .ok_or("error: mediaType is not a valid string")?;
                let mut out = None;
                match media_type {
                    "application/vnd.oci.image.manifest.v1+json"
                    | "application/vnd.docker.distribution.manifest.v2+json" => {
                        eprintln!("Start pulling {}... (v2)", image.to_string());
                        out = Some(handle_single_manifest_v2(
                            &args.registry,
                            &image,
                            manifest,
                            token_ref,
                            &download_dir,
                        )?)
                    }
                    "application/vnd.oci.image.index.v1+json"
                    | "application/vnd.docker.distribution.manifest.list.v2+json" => {
                        let mut found = false;
                        for m in manifest["manifests"]
                            .as_array()
                            .ok_or("error: manifests is not a valid array")?
                        {
                            if m["platform"]["architecture"]
                                .as_str()
                                .ok_or("error: architecture is not a valid string")?
                                == args.arch.as_str()
                            {
                                found = true;
                                let digest = m["digest"]
                                    .as_str()
                                    .ok_or("error: digest is not a valid string")?;
                                let manifest =
                                    get_manifest(&args.registry, &image, token_ref, Some(digest))?;
                                eprintln!(
                                    "Start pulling {}... (v2:{})",
                                    image.to_string(),
                                    args.arch.as_str()
                                );
                                out = Some(handle_single_manifest_v2(
                                    &args.registry,
                                    &image,
                                    manifest,
                                    token_ref,
                                    &download_dir,
                                )?)
                            }
                        }
                        if !found {
                            eprintln!("error: manifest for ({}) is not found", args.arch.as_str());
                            exit(1);
                        }
                    }
                    _ => {
                        eprintln!(
                            "error: unknown manifest mediaType ({}): '{}'",
                            image.image_name(),
                            media_type
                        );
                        exit(1);
                    }
                };
                let out = out.unwrap();
                let mut map = HashMap::new();
                map.insert(image.tag.clone(), out.1);
                repositories.insert(image.image_name(), map);

                manifest_out.push(out.0);
            }
            1 => {
                eprintln!("Start pulling {}... (v1)", image.to_string());
                let history = manifest["history"]
                    .as_array()
                    .ok_or("error: history is not a valid array")?
                    .iter()
                    .map(|v| v.as_object().unwrap().clone())
                    .collect::<Vec<_>>();
                let mut layer_id = String::new();
                for (i, layer) in manifest["fsLayers"]
                    .as_array()
                    .ok_or("error: fsLayers is not a valid array")?
                    .iter()
                    .enumerate()
                {
                    let digest = layer["blobSum"]
                        .as_str()
                        .ok_or("error: blobSum is not a valid string")?;
                    let image_json_bytes = history[i]["v1Compatibility"]
                        .as_str()
                        .ok_or("error: v1Compatibility is not a valid string")?
                        .as_bytes();
                    let image_json: HashMap<String, serde_json::Value> =
                        serde_json::from_slice(image_json_bytes)?;
                    layer_id = image_json["id"].as_str().unwrap().to_string();
                    let layer_dir = Path::new(&download_dir).join(&layer_id);
                    fs::create_dir_all(&layer_dir)?;
                    fs::write(layer_dir.join("VERSION"), b"1.0")?;
                    fs::write(layer_dir.join("json"), image_json_bytes)?;
                    fetch_blob(
                        &args.registry,
                        &image,
                        token_ref,
                        digest,
                        &layer_dir.join("layer.tar"),
                    )?;
                }
                repositories.insert(
                    image.image_name(),
                    vec![(image.tag.clone(), layer_id)].into_iter().collect(),
                );
            }
            _ => {
                eprintln!("error: unsupported schema version: {}", schema_version);
                exit(1);
            }
        }
    }

    let repositories_bytes = serde_json::to_vec(&repositories)?;
    fs::write(
        Path::new(&download_dir).join("repositories"),
        &repositories_bytes,
    )?;

    let manifests_bytes = serde_json::to_vec(&manifest_out)?;
    fs::write(
        Path::new(&download_dir).join("manifest.json"),
        &manifests_bytes,
    )?;

    let w: Box<dyn Write> = if args.out.as_ref().filter(|x| x.as_str() == "-").is_some() {
        Box::new(stdout())
    } else {
        eprintln!("Saved to {}", out_name);
        Box::new(File::create(out_name.as_str())?)
    };

    tar::Builder::new(w).append_dir_all(".", download_dir)?;

    Ok(())
}
