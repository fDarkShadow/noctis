use std::sync::Arc;

use serde_json::Value;
use tracing::{debug, info, warn};

use crate::error::Result;
use crate::model::finding::Finding;
use crate::model::step::{LoopConfig, Step};
use crate::model::test_def::TestDef;
use crate::oob::OobServer;

use super::context::Context;
use super::step::execute_step;

pub struct Runner {
    pub oob_server: Option<Arc<OobServer>>,
}

impl Runner {
    pub fn new(oob_server: Option<Arc<OobServer>>) -> Self {
        Self { oob_server }
    }

    pub async fn run(
        &self,
        def: &TestDef,
        target_host: impl Into<String>,
        target_port: Option<u16>,
        target_service: &str,
    ) -> Result<Vec<Finding>> {
        let mut ctx = Context::new(
            target_host,
            target_port,
            target_service,
            self.oob_server.clone(),
        );
        ctx.seed_vars(&def.vars);

        info!(test = %def.uid, name = %def.name, target = %ctx.target_label(), "starting test");

        let steps = &def.steps;
        let mut i = 0;
        while i < steps.len() {
            let step = &steps[i];
            debug!(step = %step.id, action = %step.action, "executing step");

            let stop = if let Some(loop_cfg) = &step.loop_cfg {
                // Group this loop step with immediately following non-loop steps so
                // a match step sees the probe result from the same iteration.
                // wait_oob is excluded — it's a one-shot wait that must run after
                // the full injection loop, not once per iteration.
                let tail = steps[i + 1..]
                    .iter()
                    .take_while(|s| s.loop_cfg.is_none() && s.action != "wait_oob")
                    .count();
                let group = &steps[i..i + 1 + tail];
                let stop = run_loop_group(group, loop_cfg, def, &mut ctx).await?;
                i += 1 + tail;
                stop
            } else {
                i += 1;
                execute_step(step, def, &mut ctx, None).await?
            };

            if stop {
                info!(step = %step.id, "stop requested — halting test");
                break;
            }
        }

        info!(test = %def.uid, findings = ctx.findings.len(), "test complete");

        Ok(ctx.findings)
    }
}

async fn run_loop_group(
    steps: &[Step],
    cfg: &LoopConfig,
    def: &TestDef,
    ctx: &mut Context,
) -> Result<bool> {
    let items: Vec<Value> = if let Some(list) = &cfg.over {
        list.iter()
            .map(|v| serde_json::to_value(v).unwrap_or(Value::Null))
            .collect()
    } else if let Some(count) = cfg.count {
        (0..count).map(|i| Value::Number(i.into())).collect()
    } else {
        warn!(step = %steps[0].id, "loop has neither 'over' nor 'count'");
        return Ok(false);
    };

    let var = cfg.var.as_str();
    for item in items {
        for step in steps {
            // Pass the loop variable to every step in the group so templates like
            // {{current_path}} in evidence strings resolve to the current item.
            if execute_step(step, def, ctx, Some((var, item.clone()))).await? {
                return Ok(true);
            }
        }
    }

    Ok(false)
}
