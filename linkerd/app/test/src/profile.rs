pub use linkerd2_app_core::{dns, profiles::*};

pub fn resolver<T>() -> crate::resolver::Profiles<T>
where
    T: std::hash::Hash + Eq + std::fmt::Debug,
{
    crate::resolver::Resolver::new()
}

pub fn with_name(name: &str) -> Profile {
    use std::str::FromStr;
    let name = dns::Name::from_str(name).expect("non-ascii characters in DNS name! 😢");
    Profile {
        name: Some(name),
        ..Default::default()
    }
}
