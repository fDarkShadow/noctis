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
    ) -> Result<Vec<Finding>> {
        let mut ctx = Context::new(target_host, target_port, self.oob_server.clone());
        ctx.seed_vars(&def.vars);

        info!(test = %def.uid, target = %ctx.target_label(), "starting test");

        for step in &def.steps {
            debug!(step = %step.id, action = %step.action, "executing step");

            let stop = if let Some(loop_cfg) = &step.loop_cfg {
                run_loop(step, loop_cfg, def, &mut ctx).await?
            } else {
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

async fn run_loop(step: &Step, cfg: &LoopConfig, def: &TestDef, ctx: &mut Context) -> Result<bool> {
    let items: Vec<Value> = if let Some(list) = &cfg.over {
        list.iter().map(|v| serde_json::to_value(v).unwrap_or(Value::Null)).collect()
    } else if let Some(count) = cfg.count {
        (0..count).map(|i| Value::Number(i.into())).collect()
    } else {
        warn!(step = %step.id, "loop has neither 'over' nor 'count'");
        return Ok(false);
    };

    for item in items {
        if execute_step(step, def, ctx, Some((cfg.var.as_str(), item))).await? {
            return Ok(true);
        }
    }

    Ok(false)
}
