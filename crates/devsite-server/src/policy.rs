//! The one place that decides who may see what.
//!
//! The profile, ticket, and capability paths all route through [`can_view`]. Keeping it
//! single means the two can never disagree — a resource hidden from Bob's view of a
//! profile is also a resource he cannot obtain a capability for.

use devsite_proto::AccountId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Visibility {
    Public,
    Private,
    Shared,
}

impl Visibility {
    pub fn as_str(&self) -> &'static str {
        match self {
            Visibility::Public => "public",
            Visibility::Private => "private",
            Visibility::Shared => "shared",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "public" => Some(Visibility::Public),
            "private" => Some(Visibility::Private),
            "shared" => Some(Visibility::Shared),
            _ => None,
        }
    }
}

/// Whether `viewer` may see a resource owned by `owner`.
///
/// `shared_with` is the set of accounts the resource was explicitly shared with. Note that
/// an anonymous viewer (`None`) can only ever see public resources — there is no path
/// where a missing session widens access.
pub fn can_view(
    viewer: Option<AccountId>,
    owner: AccountId,
    visibility: Visibility,
    shared_with: &[AccountId],
) -> bool {
    match visibility {
        Visibility::Public => true,
        Visibility::Private => viewer == Some(owner),
        Visibility::Shared => {
            viewer == Some(owner) || viewer.is_some_and(|v| shared_with.contains(&v))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: AccountId = AccountId::from_bytes([1; 16]);
    const BOB: AccountId = AccountId::from_bytes([2; 16]);
    const MALLORY: AccountId = AccountId::from_bytes([3; 16]);

    #[test]
    fn public_resources_are_visible_to_everyone_including_strangers() {
        assert!(can_view(None, ALICE, Visibility::Public, &[]));
        assert!(can_view(Some(BOB), ALICE, Visibility::Public, &[]));
    }

    #[test]
    fn private_resources_are_visible_only_to_their_owner() {
        assert!(can_view(Some(ALICE), ALICE, Visibility::Private, &[]));
        assert!(!can_view(Some(BOB), ALICE, Visibility::Private, &[]));
        assert!(!can_view(None, ALICE, Visibility::Private, &[]));
    }

    #[test]
    fn shared_resources_reach_the_named_viewers_and_no_one_else() {
        let shared = [BOB];
        assert!(can_view(Some(ALICE), ALICE, Visibility::Shared, &shared));
        assert!(can_view(Some(BOB), ALICE, Visibility::Shared, &shared));
        assert!(!can_view(Some(MALLORY), ALICE, Visibility::Shared, &shared));
        assert!(!can_view(None, ALICE, Visibility::Shared, &shared));
    }

    #[test]
    fn an_empty_share_list_is_not_a_wildcard() {
        // A "shared" resource with nobody named must behave like a private one rather
        // than falling open.
        assert!(!can_view(Some(BOB), ALICE, Visibility::Shared, &[]));
        assert!(can_view(Some(ALICE), ALICE, Visibility::Shared, &[]));
    }
}
