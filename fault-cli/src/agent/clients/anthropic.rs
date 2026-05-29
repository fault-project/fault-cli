use anyhow::Result;
use async_trait::async_trait;
use swiftide::integrations;
use swiftide::integrations::fastembed::FastEmbed;
use swiftide_core::ChatCompletion;
use swiftide_core::ChatCompletionStream;
use swiftide_core::EmbeddingModel;
use swiftide_core::Embeddings;
use swiftide_core::LanguageModelWithBackOff;
use swiftide_core::SimplePrompt;
use swiftide_core::chat_completion::errors::LanguageModelError;

#[derive(Debug, Clone)]
pub struct AnthropicClient {
    inner: LanguageModelWithBackOff<integrations::anthropic::Anthropic>,
    embedder: FastEmbed,
}

impl AnthropicClient {
    pub fn new(
        inner: LanguageModelWithBackOff<integrations::anthropic::Anthropic>,
        embedder: FastEmbed,
    ) -> Self {
        Self { inner, embedder }
    }
}

#[async_trait]
impl ChatCompletion for AnthropicClient {
    async fn complete(
        &self,
        request: &swiftide_core::chat_completion::ChatCompletionRequest,
    ) -> Result<
        swiftide_core::chat_completion::ChatCompletionResponse,
        LanguageModelError,
    > {
        self.inner.complete(request).await
    }

    async fn complete_stream(
        &self,
        request: &swiftide_core::chat_completion::ChatCompletionRequest,
    ) -> ChatCompletionStream {
        self.inner.complete_stream(request).await
    }
}

#[async_trait]
impl SimplePrompt for AnthropicClient {
    async fn prompt(
        &self,
        prompt: swiftide_core::prompt::Prompt,
    ) -> Result<String, LanguageModelError> {
        self.inner.prompt(prompt).await
    }

    fn name(&self) -> &'static str {
        self.inner.name()
    }
}

#[async_trait]
impl EmbeddingModel for AnthropicClient {
    async fn embed(
        &self,
        input: Vec<String>,
    ) -> Result<Embeddings, LanguageModelError> {
        self.embedder.embed(input).await
    }

    fn name(&self) -> &'static str {
        self.embedder.name()
    }
}

pub fn get_client(
    prompt_model: &str,
    _embed_model: &str,
) -> Result<AnthropicClient> {
    tracing::debug!(
        "Creating Anthropic client with prompt model {}",
        prompt_model,
    );

    let anthropic_client = integrations::anthropic::Anthropic::builder()
        .default_prompt_model(prompt_model)
        .build()?;

    let llm =
        LanguageModelWithBackOff::new(anthropic_client, Default::default());

    let embedder = FastEmbed::builder().batch_size(10).build()?;

    Ok(AnthropicClient::new(llm, embedder))
}
