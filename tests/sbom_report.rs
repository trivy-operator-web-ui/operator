use std::{collections::HashSet, fs, time::Duration};

use anyhow::{Ok, Result};
use kube::{
    Api, Client,
    api::{DeleteParams, ListParams, PostParams},
};
use tokio::{sync::OnceCell, time::sleep};

mod common;

#[tokio::test]
async fn controller_consumes() -> Result<()> {
    Ok(())
}