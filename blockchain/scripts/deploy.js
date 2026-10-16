// Deploys IncidentLedger and writes its address + ABI for the Python backend.
const fs = require("fs");
const path = require("path");
const hre = require("hardhat");

async function main() {
  const [deployer] = await hre.ethers.getSigners();
  const Ledger = await hre.ethers.getContractFactory("IncidentLedger");
  const ledger = await Ledger.deploy();
  await ledger.waitForDeployment();
  const address = await ledger.getAddress();

  const artifact = await hre.artifacts.readArtifact("IncidentLedger");
  const outDir = path.join(__dirname, "..", "deployments");
  fs.mkdirSync(outDir, { recursive: true });
  const outFile = path.join(outDir, "IncidentLedger.json");
  fs.writeFileSync(outFile, JSON.stringify({
    address,
    abi: artifact.abi,
    network: hre.network.name,
    chainId: Number((await hre.ethers.provider.getNetwork()).chainId),
    deployer: deployer.address,
    deployedAt: new Date().toISOString(),
  }, null, 2));

  console.log(`IncidentLedger deployed to ${address} by ${deployer.address}`);
  console.log(`Wrote ${outFile}`);
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
