use uuid::Uuid;

pub fn name_to_uuid(name: &str) -> u128 {
    Uuid::new_v3(
        &Uuid::NAMESPACE_DNS,
        format!("OfflinePlayer:{}", name).as_bytes(),
    )
    .as_u128()
}
