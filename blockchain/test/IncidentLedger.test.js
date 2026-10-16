const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("IncidentLedger", function () {
  const hash = "0x" + "ab".repeat(32);

  async function deploy() {
    const [owner, other] = await ethers.getSigners();
    const ledger = await (await ethers.getContractFactory("IncidentLedger")).deploy();
    return { ledger, owner, other };
  }

  it("records and returns an incident", async function () {
    const { ledger, owner } = await deploy();
    await expect(ledger.recordIncident("INC-1", 1700000000, "cam-01", hash))
      .to.emit(ledger, "IncidentRecorded")
      .withArgs("INC-1", "cam-01", 1700000000, hash, owner.address);

    const r = await ledger.getIncident("INC-1");
    expect(r.exists).to.equal(true);
    expect(r.timestamp).to.equal(1700000000n);
    expect(r.cameraId).to.equal("cam-01");
    expect(r.evidenceHash).to.equal(hash);
    expect(r.recorder).to.equal(owner.address);
    expect(await ledger.incidentCount()).to.equal(1n);
    expect(await ledger.incidentIdAt(0)).to.equal("INC-1");
  });

  it("verifies evidence hashes", async function () {
    const { ledger } = await deploy();
    await ledger.recordIncident("INC-1", 1, "cam-01", hash);
    expect(await ledger.verifyEvidence("INC-1", hash)).to.equal(true);
    expect(await ledger.verifyEvidence("INC-1", "0x" + "cd".repeat(32))).to.equal(false);
    expect(await ledger.verifyEvidence("INC-404", hash)).to.equal(false);
  });

  it("is append-only: an incident cannot be overwritten", async function () {
    const { ledger } = await deploy();
    await ledger.recordIncident("INC-1", 1, "cam-01", hash);
    await expect(ledger.recordIncident("INC-1", 2, "cam-02", "0x" + "cd".repeat(32)))
      .to.be.revertedWithCustomError(ledger, "AlreadyRecorded");
  });

  it("rejects writes from unauthorised accounts", async function () {
    const { ledger, other } = await deploy();
    await expect(ledger.connect(other).recordIncident("INC-1", 1, "cam-01", hash))
      .to.be.revertedWithCustomError(ledger, "NotRecorder");
    await expect(ledger.connect(other).setRecorder(other.address, true))
      .to.be.revertedWithCustomError(ledger, "NotOwner");
  });

  it("lets the owner authorise another recorder", async function () {
    const { ledger, other } = await deploy();
    await ledger.setRecorder(other.address, true);
    await ledger.connect(other).recordIncident("INC-2", 1, "cam-01", hash);
    expect((await ledger.getIncident("INC-2")).recorder).to.equal(other.address);
  });

  it("rejects empty ids and zero hashes", async function () {
    const { ledger } = await deploy();
    await expect(ledger.recordIncident("", 1, "cam-01", hash))
      .to.be.revertedWithCustomError(ledger, "InvalidInput");
    await expect(ledger.recordIncident("INC-1", 1, "cam-01", ethers.ZeroHash))
      .to.be.revertedWithCustomError(ledger, "InvalidInput");
  });
});
