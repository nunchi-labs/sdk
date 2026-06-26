use crate::CustomOperation;
use commonware_codec::{DecodeExt, Encode};

#[test]
fn operation_codec_uses_stable_tags() {
    let set = CustomOperation::SetValue { value: 7 };
    let clear = CustomOperation::ClearValue;

    assert_eq!(set.encode()[0], 0);
    assert_eq!(clear.encode()[0], 1);
    assert_eq!(CustomOperation::decode(set.encode()).unwrap(), set);
    assert_eq!(CustomOperation::decode(clear.encode()).unwrap(), clear);
    assert!(CustomOperation::decode([99].as_slice()).is_err());
}
