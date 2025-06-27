use std::result::Result::Ok;

mod kubedata;
mod dto;
mod utils;

mod controller;
use controller::start_controller;

mod api;
use api::start_api;

mod state;
use state::State;

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    let state = State::default();

    let controller = start_controller(state.clone());
    let api = start_api(state.clone());

    tokio::join!(controller, api).1?;

    Ok(())
}