use super::*;

#[test]
fn it_works_nicely() {
    use time::{Date, Month};
    let secret_access_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    let creq = "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/iam/aws4_request\nf536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";
    let date = Date::from_calendar_date(2015, Month::August, 30).expect("Hardcoded date");

    let normal_signing_key:SigningKey = KeyBuilder::default()
        .secret_access_key(secret_access_key)
        .date(date)
        .region("us-east-1")
        .service("iam")
        .aws_signing_key();

    let date_key:DateKey = KeyBuilder::default()
        .secret_access_key(secret_access_key)
        .date(date)
        .date_key();
    let date_region_key:DateRegionKey = KeyBuilder::from(date_key)
        .region("us-east-1")
        .date_region_key();
    let date_region_service_key:DateRegionServiceKey = KeyBuilder::from(date_region_key)
        .service("iam")
        .date_region_service_key();
    let aws_signing_key:SigningKey = KeyBuilder::from(date_region_service_key).aws_signing_key();

    assert_eq!(aws_signing_key,normal_signing_key);

    let _custom_signing_key:SigningKey = KeyBuilder::new("PROMPT4")
        .secret_access_key(secret_access_key)
        .date(date)
        .region("borders-are-fake-1")
        .service("top")
        .signing_key("prompt4_request");

    let signer = Signer::from(normal_signing_key);

    let signature = signer.sign(creq.as_bytes());

    let expected = "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7";
    assert_eq!(expected, &signature);
}
