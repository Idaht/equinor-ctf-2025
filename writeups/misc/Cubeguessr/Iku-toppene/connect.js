import { io } from "socket.io-client";

import Vec3 from "vec3";
import createChunk from "prismarine-chunk";

const ChunkColumn = createChunk("1.12.2");

const socket = io("https://ikutoppene-REDACTED-web.ept.gg", {
  transports: ["websocket"],
});

socket.on("connect", () => {
  console.log("Connected to server");
  socket.emit("startGame", {
    viewDistance: 2,
    minecraftVersion: "1.12.2",
  });
});

socket.on("disconnect", () => {
  console.log("Disconnected from server");
});

socket.on("loadChunk", (data) => {
  const chunk_pos = new Vec3(data.x, 0, data.z);
  let ch = ChunkColumn.fromJson(data.chunk)

  const p = new Vec3(0, 4, 0) // y-level 4
  let line = "";
  for (p.z = 0; p.z < 16; p.z++) {
    for (p.x = 0; p.x < 16; p.x++) {
      let block = ch.getBlock(p);
      if (block.type != 7) {
        line += "0,";
        continue;
      }
      line += "1,";
    }
    line += "\n";
  }
  console.log(line);
});
