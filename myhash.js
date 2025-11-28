import bcrypt from "bcrypt";

const password = "jnt2026";
const hash = await bcrypt.hash(password, 10);

console.log("Hash:", hash);

