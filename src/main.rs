fn main() {
    let person = std::env::args().nth(1).unwrap();

    match &person[..] {
        "A" => speke::alice(),
        "B" => speke::bob(),
        _ => panic!("Wrong argument"),
    }
}
