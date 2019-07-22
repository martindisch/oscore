use oscore::edhoc::Message1;

fn main() {
    let msg = Message1 {
        r#type: 1,
        suite: 0,
        x_u: vec![0, 1, 2, 3],
        c_u: vec![195],
    };
    let mut bytes = oscore::edhoc::serialize_message_1(msg).unwrap();
    println!("{}", hexstring(&bytes));
    println!(
        "{:#?}",
        oscore::edhoc::deserialize_message_1(&mut bytes).unwrap()
    );
}

fn hexstring(slice: &[u8]) -> String {
    slice
        .iter()
        .map(|n| format!("{:02x}", n))
        .collect::<Vec<String>>()
        .join(" ")
}
