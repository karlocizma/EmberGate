//! Export the same documentation payload used by in-app Help for the static site.
#[allow(dead_code)]
#[path = "../src/documentation.rs"]
mod documentation;
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string(documentation::embedded())?);
    Ok(())
}
