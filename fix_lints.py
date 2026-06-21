import re

with open("src/minecraft/session.rs", "r") as f:
    content = f.read()
content = content.replace("use valence_protocol::packets::handshaking::handshake_c2s::HandshakeNextState as ValenceHandshakeNextState;", "")
with open("src/minecraft/session.rs", "w") as f:
    f.write(content)

with open("src/vless/wire.rs", "r") as f:
    content = f.read()
content = content.replace("use crate::vless::types::{VlessAddress, VlessId, VlessTarget};", "use crate::vless::types::{VlessAddress, VlessId};")
with open("src/vless/wire.rs", "w") as f:
    f.write(content)

with open("src/minecraft/play.rs", "r") as f:
    content = f.read()
content = content.replace("let id = send_keepalive(&mut server).await.unwrap();", "let _id = send_keepalive(&mut server).await.unwrap();")
with open("src/minecraft/play.rs", "w") as f:
    f.write(content)

with open("src/protocol.rs", "r") as f:
    content = f.read()
content = content.replace("let mut cur = Cursor::new(vec![255, 255, 3]);", "let cur = Cursor::new(vec![255, 255, 3]);")
content = content.replace("let mut cur_slice = cur.into_inner();", "let cur_slice = cur.into_inner();")
with open("src/protocol.rs", "w") as f:
    f.write(content)
