use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use valence_protocol::uuid::Uuid;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Whitelist {
    entries: Vec<WhitelistEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhitelistEntry {
    pub name: Option<String>,
    pub uuid: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
struct MinecraftWhitelistEntry {
    uuid: String,
    name: String,
}

impl Whitelist {
    pub fn from_cli(names: Vec<String>, uuids: Vec<Uuid>) -> Result<Self> {
        let mut entries = Vec::with_capacity(names.len() + uuids.len());

        for name in names {
            entries.push(WhitelistEntry::from_name(name)?);
        }

        for uuid in uuids {
            entries.push(WhitelistEntry {
                name: None,
                uuid: Some(uuid),
            });
        }

        Ok(Self { entries })
    }

    pub fn load_json(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading whitelist file {}", path.display()))?;
        let decoded: Vec<MinecraftWhitelistEntry> = serde_json::from_str(&raw)
            .with_context(|| format!("parsing Minecraft whitelist file {}", path.display()))?;

        let mut entries = Vec::with_capacity(decoded.len());
        for entry in decoded {
            entries.push(WhitelistEntry::from_minecraft(entry)?);
        }

        Ok(Self { entries })
    }

    pub fn extend(&mut self, other: Self) {
        self.entries.extend(other.entries);
    }

    pub fn is_enabled(&self) -> bool {
        !self.entries.is_empty()
    }

    pub fn allows(&self, username: &str, uuid: &Uuid) -> bool {
        !self.is_enabled()
            || self.entries.iter().any(|entry| {
                entry
                    .name
                    .as_deref()
                    .is_some_and(|name| name.eq_ignore_ascii_case(username))
                    || entry.uuid.as_ref().is_some_and(|allowed| allowed == uuid)
            })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl WhitelistEntry {
    pub fn from_name(name: String) -> Result<Self> {
        let name = name.trim();
        if name.is_empty() {
            bail!("whitelist username must not be empty");
        }

        Ok(Self {
            name: Some(name.to_owned()),
            uuid: None,
        })
    }

    fn from_minecraft(entry: MinecraftWhitelistEntry) -> Result<Self> {
        let name = entry.name.trim();
        if name.is_empty() {
            bail!("whitelist entry has an empty name");
        }

        Ok(Self {
            name: Some(name.to_owned()),
            uuid: Some(parse_uuid(&entry.uuid)?),
        })
    }
}

pub fn parse_uuid(input: &str) -> Result<Uuid> {
    Uuid::parse_str(input.trim()).with_context(|| format!("parsing UUID {input}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_whitelist_allows_everyone() {
        let whitelist = Whitelist::default();
        let uuid = parse_uuid("b50ad385-829d-3141-a216-7e7d7539ba7f").unwrap();

        assert!(whitelist.allows("Notch", &uuid));
    }

    #[test]
    fn username_match_is_case_insensitive() {
        let whitelist = Whitelist::from_cli(vec!["Notch".to_owned()], vec![]).unwrap();
        let uuid = parse_uuid("00000000-0000-0000-0000-000000000000").unwrap();

        assert!(whitelist.allows("notch", &uuid));
    }

    #[test]
    fn uuid_match_allows_different_name() {
        let uuid = parse_uuid("b50ad385-829d-3141-a216-7e7d7539ba7f").unwrap();
        let whitelist = Whitelist::from_cli(vec![], vec![uuid]).unwrap();

        assert!(whitelist.allows("SomeoneElse", &uuid));
    }

    #[test]
    fn rejects_non_matching_user_when_enabled() {
        let whitelist = Whitelist::from_cli(vec!["Allowed".to_owned()], vec![]).unwrap();
        let uuid = parse_uuid("00000000-0000-0000-0000-000000000000").unwrap();

        assert!(!whitelist.allows("Intruder", &uuid));
    }

    #[test]
    fn from_cli_rejects_empty_name() {
        assert!(Whitelist::from_cli(vec![" ".to_owned()], vec![]).is_err());
    }

    #[test]
    fn load_json_handles_minecraft_format() {
        let temp = std::env::temp_dir().join("whitelist.json");
        let json = r#"[{"uuid":"b50ad385-829d-3141-a216-7e7d7539ba7f","name":"Notch"}]"#;
        std::fs::write(&temp, json).unwrap();

        let whitelist = Whitelist::load_json(&temp).unwrap();
        assert!(whitelist.is_enabled());
        assert_eq!(whitelist.len(), 1);
        assert!(whitelist.allows(
            "notch",
            &parse_uuid("b50ad385-829d-3141-a216-7e7d7539ba7f").unwrap()
        ));

        std::fs::remove_file(temp).unwrap();
    }

    #[test]
    fn extend_merges_whitelists() {
        let mut w1 = Whitelist::from_cli(vec!["A".to_owned()], vec![]).unwrap();
        let w2 = Whitelist::from_cli(vec!["B".to_owned()], vec![]).unwrap();
        w1.extend(w2);

        assert_eq!(w1.len(), 2);
        assert!(w1.allows("a", &Uuid::nil()));
        assert!(w1.allows("b", &Uuid::nil()));
    }

    #[test]
    fn parse_uuid_rejects_invalid() {
        assert!(parse_uuid("invalid").is_err());
    }
}
