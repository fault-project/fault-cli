use std::sync::Arc;
use std::fmt;

use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;
use swiftide::integrations;
use swiftide_core::ChatCompletion;
use swiftide_core::DynClone;
use swiftide_core::EmbeddingModel;
use swiftide_core::LanguageModelWithBackOff;
use swiftide_core::SimplePrompt;
use clap::ValueEnum;
use std::str::FromStr;

pub(crate) mod gemini;
pub(crate) mod ollama;
pub(crate) mod openai;
pub(crate) mod openrouter;

#[derive(ValueEnum, Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SupportedLLMClient {
    #[value(alias = "google", alias = "vertex", alias = "gemini-pro")]
    Gemini,
    #[value(alias = "openai", alias = "oai")]
    OpenAI,
    #[value(alias = "openrouter", alias = "router", alias = "or")]
    OpenRouter,
    #[value(alias = "local")]
    Ollama,
}

impl Default for SupportedLLMClient {
    fn default() -> Self {
        SupportedLLMClient::OpenAI
    }
}

impl FromStr for SupportedLLMClient {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        <Self as ValueEnum>::from_str(s, /* ignore_case = */ true)
    }
}

impl fmt::Display for SupportedLLMClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            SupportedLLMClient::Gemini => "gemini",
            SupportedLLMClient::OpenAI => "openai",
            SupportedLLMClient::OpenRouter => "openrouter",
            SupportedLLMClient::Ollama => "ollama",
        };
        write!(f, "{name}")
    }
}

pub trait LLM:
    ChatCompletion
    + SimplePrompt
    + EmbeddingModel
    + Send
    + Sync
    + std::fmt::Debug
    + DynClone
{
}

impl<T> LLM for T where
    T: ChatCompletion
        + SimplePrompt
        + EmbeddingModel
        + Send
        + Sync
        + std::fmt::Debug
        + DynClone
{
}

pub fn get_client(
    llm: SupportedLLMClient,
    prompt_model: &str,
    embed_model: &str,
) -> Result<Arc<dyn LLM>> {
    match llm {
        SupportedLLMClient::OpenAI => {
            Ok(Arc::new(openai::get_client(prompt_model, embed_model)?))
        }
        SupportedLLMClient::OpenRouter => {
            Ok(Arc::new(openrouter::get_client(prompt_model, embed_model)?))
        }
        SupportedLLMClient::Ollama => {
            Ok(Arc::new(ollama::get_client(prompt_model, embed_model)?))
        }
        SupportedLLMClient::Gemini => {
            Ok(Arc::new(gemini::get_client(prompt_model, embed_model)?))
        }
    }
}

pub fn get_llm_client(
    llm: SupportedLLMClient,
    prompt_model: &str,
    embed_model: &str,
) -> Result<Box<dyn ChatCompletion>> {
    match llm {
        SupportedLLMClient::OpenAI => {
            Ok(Box::new(openai::get_client(prompt_model, embed_model)?))
        }
        SupportedLLMClient::OpenRouter => {
            Ok(Box::new(openrouter::get_client(prompt_model, embed_model)?))
        }
        SupportedLLMClient::Ollama => {
            Ok(Box::new(ollama::get_client(prompt_model, embed_model)?))
        }
        SupportedLLMClient::Gemini => {
            Ok(Box::new(gemini::get_client(prompt_model, embed_model)?))
        }
    }
}
