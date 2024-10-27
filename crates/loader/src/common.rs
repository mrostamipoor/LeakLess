use anyhow::ensure;
use serde::{Deserialize, Serialize};
use spin_manifest::Variable;
//use zeroize::Zeroize;
/// Variable configuration.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RawVariable {
    /// If set, this variable is required; may not be set with `default`.
    #[serde(default)]
    pub required: bool,
    /// If set, the default value for this variable; may not be set with `required`.
    #[serde(default)]
    pub default: Option<String>,
    /// If set, this variable should be treated as sensitive.
    #[serde(default)]
    pub secret: bool,
    /// If set, this variable's value should be treated as a encrypted sensitive (e.g. keep encrypted in memory).
    #[serde(default)]
    pub leaklesssecret: bool,
    /// If set, it determines the type of the service that the IO process should be performed (support: s3-sign,jwt-decode,jwt-sign).
    #[serde(default)]
    pub leaklessoperation: Option<String>,
}

impl TryFrom<RawVariable> for Variable {
    type Error = anyhow::Error;

    fn try_from(var: RawVariable) -> Result<Self, Self::Error> {
        ensure!(
            var.required ^ var.default.is_some(),
            "variable has both `required` and `default` set"
        );
        Ok(Variable {
            default: var.default,
            secret: var.secret,
            leaklesssecret: var.leaklesssecret,
            leaklessoperation: var.leaklessoperation,
        })
    }
}
/*impl Zeroize for RawVariable {
    fn zeroize(&mut self) {
        // Set all fields to default or zero values.
        self.required = Default::default();
        self.default = Default::default();
        self.secret = Default::default();
        self.leakless = Default::default();
    }
}*/