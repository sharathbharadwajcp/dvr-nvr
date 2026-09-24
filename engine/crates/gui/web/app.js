// DVR/NVR Digital Video Forensics Platform - GUI Application Logic
// Open Digital Evidence Platform

document.addEventListener("DOMContentLoaded", () => {
  setupNavigation();
  setupAcquireScreen();
  setupIdentifyScreen();
  setupParseScreen();
  setupTimelineScreen();
  setupReportScreen();
});

function setupNavigation() {
  const navBtns = document.querySelectorAll(".nav-btn");
  const screens = document.querySelectorAll(".screen-panel");
  const pageTitle = document.getElementById("page-title");

  const titles = {
    "screen-acquire": "Screen 1: New Case & Forensic Acquisition",
    "screen-identify": "Screen 2: Pre-Acquisition Device & Architecture Identification",
    "screen-parse": "Screen 3: Declarative Grammar Demuxing & Deep Video Carving",
    "screen-timeline": "Screen 4: Spatial-Temporal Timeline & AI Video Analytics",
    "screen-report": "Screen 5: Legal-Admissibility Certificate (Section 63 BSA 2023)",
  };

  navBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      const targetId = btn.getAttribute("data-target");

      navBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");

      screens.forEach((s) => s.classList.remove("active"));
      const targetScreen = document.getElementById(targetId);
      if (targetScreen) targetScreen.classList.add("active");

      if (pageTitle && titles[targetId]) {
        pageTitle.innerText = titles[targetId];
      }
    });
  });
}

// 1. ACQUIRE SCREEN
function setupAcquireScreen() {
  const btn = document.getElementById("btn-run-acquire");
  const resultsCard = document.getElementById("acquire-results");

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.innerText = "Acquiring Evidence (Computing Hashes)...";

    const payload = {
      image_path: document.getElementById("acq-source").value,
      case_name: document.getElementById("acq-case").value,
      output_dir: document.getElementById("acq-out").value,
    };

    try {
      const res = await fetch("/api/acquire", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (data.success) {
        document.getElementById("acq-bytes").innerText = data.manifest.total_bytes.toLocaleString();
        document.getElementById("acq-blocks").innerText = data.manifest.block_count;
        document.getElementById("acq-sha256").innerText = data.manifest.whole_image_sha256;
        document.getElementById("acq-md5").innerText = data.manifest.whole_image_md5;
        document.getElementById("acq-blake3").innerText = data.manifest.block_hashes[0] || "-";

        resultsCard.style.display = "block";
      } else {
        alert("Acquisition failed: " + (data.error || "Unknown error"));
      }
    } catch (err) {
      alert("Error contacting forensic engine: " + err.message);
    } finally {
      btn.disabled = false;
      btn.innerText = "Acquire Evidence Image (Read-Only Streaming)";
    }
  });
}

// 2. IDENTIFY SCREEN
function setupIdentifyScreen() {
  const btn = document.getElementById("btn-run-identify");
  const resultsCard = document.getElementById("ident-results");

  const runIdentification = async (imagePath) => {
    btn.disabled = true;
    btn.innerText = "Probing Signatures...";

    const payload = {
      image_path: imagePath || document.getElementById("ident-source").value,
      grammars_dir: document.getElementById("ident-grammars").value,
    };

    try {
      const res = await fetch("/api/identify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (data.success) {
        const ident = data.identification;
        document.getElementById("ident-vendor").innerText = ident.vendor;
        document.getElementById("ident-model").innerText = ident.model || "Unknown Model";
        document.getElementById("ident-chipset").innerText = ident.chipset || "Undetermined";
        document.getElementById("ident-confidence").innerText = (ident.confidence * 100).toFixed(1) + "%";

        const badgeDiv = document.getElementById("ident-tier-badge");
        if (ident.validation_tier === 1) {
          badgeDiv.innerHTML = '<span class="badge badge-tier-1">Tier 1: Synthetic Fixture Format</span>';
        } else if (ident.validation_tier === 2) {
          badgeDiv.innerHTML = '<span class="badge badge-tier-2">Tier 2: Literature-Derived Vendor Grammar</span>';
        } else if (ident.validation_tier === 3) {
          badgeDiv.innerHTML = '<span class="badge badge-tier-1">Tier 3: Physical Hardware Confirmed</span>';
        } else {
          badgeDiv.innerHTML = '<span class="badge badge-tier-0">Tier 0: Registry-Only / Unimplemented (Refer to Extension Guide)</span>';
        }

        const detailsDiv = document.getElementById("ident-details");
        detailsDiv.innerHTML = ident.details.map((d) => `&bull; ${d}`).join("<br>");

        resultsCard.style.display = "block";
      } else {
        alert("Identification failed: " + (data.error || "Unknown error"));
      }
    } catch (err) {
      alert("Error contacting forensic engine: " + err.message);
    } finally {
      btn.disabled = false;
      btn.innerText = "Run Device Identification";
    }
  };

  btn?.addEventListener("click", () => runIdentification());

  document.getElementById("btn-load-cpplus-sample")?.addEventListener("click", async () => {
    document.getElementById("ident-source").value = "../samples/fixtures/sample_cpplus.img";
    await runIdentification("../samples/fixtures/sample_cpplus.img");
  });

  document.getElementById("btn-load-uniview-sample")?.addEventListener("click", async () => {
    document.getElementById("ident-source").value = "../samples/fixtures/sample_uniview.img";
    await runIdentification("../samples/fixtures/sample_uniview.img");
  });
}

// 3. PARSE SCREEN
function setupParseScreen() {
  const btn = document.getElementById("btn-run-parse");
  const resultsCard = document.getElementById("parse-results");
  const tbody = document.querySelector("#table-parse-records tbody");

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.innerText = "Parsing Blocks & Carving Frames...";

    const payload = {
      case_dir: document.getElementById("parse-casedir").value,
    };

    try {
      const res = await fetch("/api/parse", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (data.success) {
        document.getElementById("parse-total-blocks").innerText = data.total_blocks;
        document.getElementById("parse-valid-frames").innerText = data.valid_frames;
        document.getElementById("parse-descrambled").innerText = data.descrambled_blocks;
        document.getElementById("parse-carved").innerText = data.carved_count;

        tbody.innerHTML = "";
        data.records.slice(0, 30).forEach((r) => {
          const row = document.createElement("tr");
          let statusBadge = '<span class="badge badge-pristine">VALID</span>';
          if (r.is_corrupted) {
            statusBadge = '<span class="badge badge-alert">CORRUPTED</span>';
          } else if (r.descrambled) {
            statusBadge = '<span class="badge badge-tier-2">DESCRAMBLED</span>';
          } else if (r.is_scrambled) {
            statusBadge = '<span class="badge badge-tier-0">SCRAMBLED</span>';
          }

          const tierBadge = `<span class="badge badge-tier-${r.tier || 1}">Tier ${r.tier || 1}</span>`;

          row.innerHTML = `
            <td>${r.block_index}</td>
            <td>${r.byte_offset}</td>
            <td>CH ${r.channel_id}</td>
            <td>${r.normalized_timestamp}</td>
            <td>${r.sequence_num}</td>
            <td>${statusBadge}</td>
            <td>${tierBadge}</td>
          `;
          tbody.appendChild(row);
        });

        resultsCard.style.display = "block";
      } else {
        alert("Parsing failed: " + (data.error || "Unknown error"));
      }
    } catch (err) {
      alert("Error: " + err.message);
    } finally {
      btn.disabled = false;
      btn.innerText = "Parse Structured Blocks & Deep Carve";
    }
  });
}

// 4. TIMELINE & ANALYTICS SCREEN
function setupTimelineScreen() {
  const btn = document.getElementById("btn-run-timeline");
  const resultsCard = document.getElementById("timeline-results");
  const tbody = document.querySelector("#table-ai-leads tbody");

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.innerText = "Correlating & Running AI Video Analytics...";

    const payload = {
      case_dir: document.getElementById("timeline-casedir").value,
    };

    try {
      const res = await fetch("/api/timeline-analytics", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (data.success) {
        document.getElementById("time-transitions").innerText = data.transitions_count;
        document.getElementById("time-blackouts").innerText = data.blackouts_count;
        document.getElementById("time-detections").innerText = data.detections_count;
        document.getElementById("time-leads").innerText = data.leads.length;

        tbody.innerHTML = "";
        data.leads.slice(0, 15).forEach((lead) => {
          lead.entities.forEach((ent) => {
            const row = document.createElement("tr");
            row.style.cursor = "pointer";
            row.addEventListener("click", () => {
              const player = document.getElementById("video-player-container");
              player.innerHTML = `
                <div style="text-align: left; padding: 12px;">
                  <p style="color: var(--accent-cyan); font-weight: 700; margin-bottom: 4px;">Selected Block ${lead.block_index} (Channel ${lead.channel_id})</p>
                  <p style="font-size: 0.8rem; color: #fff;">Timestamp: ${lead.normalized_timestamp}</p>
                  <p style="font-size: 0.8rem; color: var(--accent-emerald);">Motion Energy: ${lead.motion_energy.toFixed(4)}</p>
                  <p style="font-size: 0.8rem; color: #fff;">Entity: ${ent.class_label} (${(ent.confidence * 100).toFixed(0)}%)</p>
                  <p style="font-size: 0.75rem; color: var(--text-muted); margin-top: 6px;">[Raw H.264 NAL stream extracted & verified untampered]</p>
                </div>
              `;
            });

            row.innerHTML = `
              <td>${lead.block_index}</td>
              <td>CH ${lead.channel_id}</td>
              <td>${lead.normalized_timestamp}</td>
              <td><span class="badge badge-tier-2">${ent.class_label.toUpperCase()}</span></td>
              <td>${(ent.confidence * 100).toFixed(0)}%</td>
              <td>${lead.relevance_score.toFixed(2)}</td>
            `;
            tbody.appendChild(row);
          });
        });

        resultsCard.style.display = "block";
      } else {
        alert("Analytics failed: " + (data.error || "Unknown error"));
      }
    } catch (err) {
      alert("Error: " + err.message);
    } finally {
      btn.disabled = false;
      btn.innerText = "Correlate Multi-Camera Events & Run AI Analytics";
    }
  });
}

// 5. REPORT SCREEN
function setupReportScreen() {
  const btn = document.getElementById("btn-run-report");
  const resultsCard = document.getElementById("cert-results");

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    btn.innerText = "Formulating Section 63 BSA Certificate...";

    const payload = {
      case_dir: document.getElementById("cert-casedir").value,
      examiner: {
        name: document.getElementById("cert-examiner").value,
        designation: document.getElementById("cert-designation").value,
        agency: document.getElementById("cert-agency").value,
        badge_number: document.getElementById("cert-badge").value,
        laboratory: document.getElementById("cert-lab").value,
      },
    };

    try {
      const res = await fetch("/api/report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await res.json();
      if (data.success) {
        resultsCard.style.display = "block";
      } else {
        alert("Report generation failed: " + (data.error || "Unknown error"));
      }
    } catch (err) {
      alert("Error: " + err.message);
    } finally {
      btn.disabled = false;
      btn.innerText = "Generate Section 63 BSA Certificate & Case Report";
    }
  });
}
