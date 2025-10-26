# OCI Generative AI Professional - Study Guide

> **Certification Code**: 1Z0-1127-25
> **Target Audience**: Cloud Architects, AI/ML Engineers, Developers
> **Duration**: 90 minutes
> **Format**: Multiple Choice (Thật ra là chọn 1 đáp án)

---

## 📚 Table of Contents

1. [Fundamentals of Large Language Models](#fundamentals-of-llms)
2. [OCI Generative AI Service](#oci-generative-ai-service)
3. [Retrieval-Augmented Generation (RAG)](#rag-and-oracle-vector-search)
4. [OCI Generative AI Agents](#oci-generative-ai-agents)

---

## 1. Fundamentals of LLMs

### 1.1 What are Large Language Models?

**Definition**: Probabilistic models of text that compute distributions over vocabulary.

**Core Function**: Given input text, predict the most likely next word(s).

**"Large"**: Refers to the **number of trainable parameters** (typically billions).

### 1.2 LLM Architectures

| Architecture | Function | Use Cases | Examples |
|-------------|----------|-----------|----------|
| **Encoders** | Convert text → embeddings | Semantic search, classification, clustering | BERT, RoBERTa |
| **Decoders** | Generate text by predicting next token | Text generation, chat, code completion | GPT-4, Llama |
| **Encoder-Decoder** | Both encoding and decoding | Translation, sequence-to-sequence | T5, BART |

**Key Point**:
- **Encoders** → Best for **semantic search** and understanding
- **Decoders** → Best for **text generation**

### 1.3 Prompting & Prompt Engineering

**Prompting**: Changing model inputs to influence output.

**Prompt Engineering**: Refining inputs to get desired results.

#### Types of Prompting

| Type | Description | Example |
|------|-------------|---------|
| **Zero-shot** | Only task description, no examples | "Translate to French: Hello" |
| **Few-shot (k-shot)** | Include k examples | "cat→dog, hot→cold, big→?" |
| **Chain-of-Thought (CoT)** | Step-by-step reasoning | "Let's solve this step by step..." |
| **Zero-shot CoT** | Add "Let's think step by step" | Encourages reasoning without examples |

### 1.4 Decoding (Text Generation)

| Method | Description | Use Case |
|--------|-------------|----------|
| **Greedy Decoding** | Always pick the most probable token | Deterministic output |
| **Random Sampling** | Pick based on probability distribution | More diverse output |
| **Temperature** | Controls randomness (0=deterministic, 1=creative) | Balance creativity vs accuracy |
| **Top-k Sampling** | Choose from top-k highest probability tokens | Limited randomness |
| **Top-p (Nucleus)** | Choose from smallest set that adds up to p | Dynamic vocabulary |
| **Beam Search** | Generate multiple sequences, keep best | Higher quality output |

**Temperature Guidelines**:
- **Temperature = 0**: Completely deterministic
- **Temperature = 0.3-0.5**: Factual tasks
- **Temperature = 0.7-0.9**: Creative tasks
- **Temperature = 1.0**: Maximum randomness

### 1.5 Training & Fine-tuning Methods

| Method | Updates | Cost | Use Case |
|--------|---------|------|----------|
| **Fine-tuning** | All parameters | High | Best accuracy for specific tasks |
| **LoRA** | ~0.1-1% of parameters | Medium | Parameter-efficient tuning |
| **T-Few** | ~0.01% of parameters | Low | Oracle's efficient method |
| **Soft Prompting** | Special tokens only | Very Low | Task adaptation |
| **Continual Pretraining** | All parameters on new domain | Very High | Domain adaptation |

**Key Insight**: **T-Few** is Oracle's proprietary fine-tuning method that updates only ~0.01% of weights.

### 1.6 Key Challenges

| Challenge | Description | Mitigation |
|-----------|-------------|------------|
| **Hallucinations** | Generates fluent but incorrect info | Use RAG, grounding |
| **Bias** | Reflects training data biases | Content moderation, filtering |
| **Cost** | Training requires many GPUs | Use fine-tuning, not training from scratch |
| **Prompt Injection** | Malicious input manipulation | Input validation, sandboxing |
| **Data Leakage** | Exposure of training data | Privacy controls, data governance |

### 1.7 Evaluation Metrics

| Metric | Measures | Lower is Better? | Use Case |
|--------|----------|------------------|----------|
| **Perplexity** | How well model predicts tokens | ✅ Yes | Language modeling |
| **BLEU** | N-gram overlap (precision) | ❌ No | Translation |
| **ROUGE** | Recall/overlap | ❌ No | Summarization |
| **Accuracy/F1** | Classification performance | ❌ No | Classification |
| **Loss** | Prediction error | ✅ Yes | Training progress |

---

## 2. OCI Generative AI Service

### 2.1 Overview

**OCI Generative AI Service**: Fully managed, **serverless** platform for building generative AI apps.

**Key Features**:
- Single API for multiple foundation models (Cohere & Meta)
- No infrastructure management
- Pay-per-use pricing
- Built-in security and compliance

### 2.2 Pre-trained Foundation Models

#### Chat Models

| Model | Context Window | Parameters | Best For |
|-------|---------------|------------|----------|
| **Command-R** | 16k tokens | - | General chat, standard tasks |
| **Command-R-Plus** | **128k tokens** | - | Long documents, complex reasoning |
| **Meta Llama 3.1 (70B)** | 128k tokens | 70B | Open-source alternative |
| **Meta Llama 3.2/3.3** | Varies | Varies | Latest improvements |

**Important**: **Command-R-Plus** supports the **largest context window (128k tokens)**.

#### Embedding Models

**Purpose**: Convert text → vector representations for:
- Semantic search
- Clustering
- Classification
- RAG (Retrieval-Augmented Generation)

| Model | Languages | Dimensions | Input Limit |
|-------|-----------|------------|-------------|
| **Cohere embed-english** | English | 1024-d (standard), 384-d (lite) | 512 tokens/input |
| **Cohere embed-multilingual** | 100+ languages | 1024-d (standard), 384-d (lite) | 512 tokens/input |
| **V3 embed models** | Enhanced | 1024-d | Better for noisy data |

**Limits**:
- Max **512 tokens per input**
- Max **96 inputs per request**

### 2.3 Prompt Parameters

| Parameter | Function | Range | Effect |
|-----------|----------|-------|--------|
| **Temperature** | Controls randomness | 0-1 | 0=deterministic, 1=diverse |
| **Top-k** | Choose from top-k tokens | 1-n | Limits vocabulary |
| **Top-p** | Nucleus sampling | 0-1 | Dynamic token selection |
| **Frequency Penalty** | Reduces repetition by frequency | 0-1 | Based on how often token appears |
| **Presence Penalty** | Penalizes any repetition | 0-1 | Binary (appeared or not) |
| **Preamble Override** | Change tone/style | Text | "You are a pirate..." |

**Key Difference**:
- **Frequency Penalty**: Proportional to how many times token appeared
- **Presence Penalty**: Same penalty after first occurrence

### 2.4 Customization Options Comparison

| Approach | Training Required | Cost | Latency | Use Case |
|----------|------------------|------|---------|----------|
| **Prompting** | No | Free | Low | Quick experimentation |
| **RAG** | No | Low | Medium | Up-to-date knowledge |
| **Fine-tuning** | Yes | High | Low (after training) | Domain-specific tasks |
| **Training from Scratch** | Yes | Very High | Low | Not recommended |

**Best Practice**: **Don't train from scratch** - expensive and data-hungry.

### 2.5 Fine-tuning Workflow

```
1. Collect domain-specific training data
2. Upload to Object Storage
3. Launch fine-tuning job (choose base model + method)
4. Training runs on GPU cluster
5. Store fine-tuned weights (encrypted in Object Storage)
6. Register model in OCI Generative AI
7. Deploy to endpoint for inference
```

### 2.6 Inference Workflow

```
User sends prompt
    ↓
API Endpoint
    ↓
Model generates output (using decoding strategies)
    ↓
Response to user
    ↓
Optional: Logging, tracing, moderation, citations
```

### 2.7 Dedicated AI Clusters

#### Fine-Tuning Clusters

**Purpose**: Train/adapt models with custom data

**Billing**: Pay only for **duration of fine-tuning**

**Formula**:
```
Cost = Units × Hourly Rate × Hours
```

**Example**: Fine-tune with 8 units for 12 hours
```
Cost = 8 × $1/hr × 12 hrs = $96
```

#### Hosting (Inference) Clusters

**Purpose**: Serve models in production

**Billing**: Minimum **744 hours/month** (24×7 commitment)

**Formula**:
```
Cost = Units × Hourly Rate × 744 hrs/month
```

**Example**: Host with 2 units
```
Monthly Cost = 2 × $Y/hr × 744 hrs = 1,488 × Y
```

#### Cluster Types by Model

| Cluster Type | Model Family | Use Case |
|-------------|--------------|----------|
| **Small Cohere Dedicated** | Cohere (small) | Fine-tuning Command-R |
| **Large Cohere Dedicated** | Cohere (large) | Fine-tuning Command-R-Plus |
| **Large Meta Dedicated** | Meta Llama | Fine-tuning Llama models |
| **Embedding Cohere Dedicated** | Cohere Embed | Embedding tasks |

**Important**: **Llama models** use **Large Meta Dedicated** clusters.

### 2.8 GPU Sizing Guidelines

| Model Size | Parameters | Recommended Units |
|------------|-----------|-------------------|
| Small | ≤13B | 4-8 units |
| Medium | 30-70B | 8-16+ units |
| Large | 100B+ | 32+ units |

**Best Practice**: Run pilot jobs to estimate time & cost.

---

## 3. RAG and Oracle Vector Search

### 3.1 What is RAG?

**Retrieval-Augmented Generation**: Combines retrieval (search) + generation (LLM).

**Why RAG?**
- LLMs have **outdated training data**
- RAG retrieves **current, relevant information**
- Grounds answers in **enterprise data**
- **No retraining required**

### 3.2 RAG Pipeline Phases

```
1. INGESTION
   Load documents → Split into chunks → Create metadata

2. EMBEDDING & STORAGE
   Convert chunks → Vectors → Store in vector database

3. RETRIEVAL
   User query → Convert to vector → Similarity search → Top-K chunks

4. GENERATION
   LLM receives: Query + Retrieved chunks → Generate answer
```

### 3.3 LangChain Integration

#### Key Components

| Component | Purpose |
|-----------|---------|
| **PromptTemplate** | Single-string inputs |
| **ChatPromptTemplate** | Multi-turn conversations with roles |
| **Memory** | Maintain conversation history |
| **RetrievalQA** | Chain retrieval + LLM together |
| **VectorStore** | Store and search embeddings |

#### What is Memory?

- LLMs are **stateless** by default
- Memory **stores previous interactions**
- LangChain **passes history** back to model
- Enables **context-aware** conversations

**Memory Workflow**:
```
1. User asks question → LangChain records it
2. LLM generates response → Also recorded
3. Next interaction → Retrieves conversation history
4. History appended to new prompt → LLM sees context
```

### 3.4 Oracle 23ai Integration

#### SELECT AI

**Purpose**: Converts **natural language → SQL queries** using OCI Generative AI

**Example**:
```sql
SELECT AI "Show me all customers who spent more than $1000 last month"
```

#### Vector Store

**Purpose**: Store embeddings in **VECTOR datatype**

**Capabilities**:
- Similarity search (cosine, dot product)
- Native SQL integration
- Scalable vector indexing

### 3.5 Vector Indexes

#### HNSW (Hierarchical Navigable Small World)

**Type**: Graph-based neighbor index

**How it Works**: Each vector links to nearby vectors across multiple layers

**Pros**:
- Very fast ANN (Approximate Nearest Neighbor) search
- Strong recall at low latency
- Best for interactive RAG/chat

**Cons**:
- Requires memory for graph
- Build time increases with size

**Best For**: Low-latency Q&A, real-time semantic search

#### IVF (Inverted File)

**Type**: Partition/cluster-based index

**How it Works**: Routes query to most relevant partitions, then searches inside

**Pros**:
- Efficient at scale
- Good throughput for large collections
- Predictable query times

**Cons**:
- Recall depends on partitions probed
- Requires tuning

**Best For**: Very large collections (millions+ vectors)

### 3.6 Similarity Metrics

| Metric | Considers | Formula | Normalized? |
|--------|-----------|---------|-------------|
| **Dot Product** | Magnitude + Angle | a·b | No |
| **Cosine Similarity** | Angle only | a·b / (‖a‖‖b‖) | Yes |
| **Euclidean Distance** | Spatial distance | √Σ(ai-bi)² | No |

**When to Use**:
- **Cosine**: Magnitude-invariant, good for text
- **Dot Product**: When magnitude matters
- **Euclidean**: Spatial relationships

### 3.7 Text Chunking

**Why Chunk?**
- LLMs have **token limits**
- Smaller chunks = **more precise retrieval**
- **Overlap** maintains semantic continuity

**Best Practices**:
- Chunk size: **200-500 tokens**
- Overlap: **10-20%**
- Preserve sentence boundaries

**Tools**:
- `TextSplitter` (LangChain)
- `RecursiveCharacterTextSplitter`

### 3.8 RAG with Oracle DB 23ai

**Complete Workflow**:

```python
# 1. Setup
from langchain_community.embeddings import OCIGenAIEmbeddings
from langchain_community.vectorstores import OracleVS
from langchain.chains import RetrievalQA

# 2. Generate embeddings
embeddings = OCIGenAIEmbeddings(
    model_id="cohere.embed-english-v3.0",
    service_endpoint="https://..."
)

# 3. Store in Oracle Vector Store
vector_store = OracleVS(
    connection_string="...",
    embedding_function=embeddings,
    table_name="document_chunks"
)

# 4. Create retrieval chain
qa_chain = RetrievalQA.from_chain_type(
    llm=ChatOCIGenAI(...),
    retriever=vector_store.as_retriever(search_kwargs={"k": 3}),
    return_source_documents=True
)

# 5. Query
result = qa_chain({"query": "What is RAG?"})
```

**Key Points**:
- Same embedding model for **indexing and querying**
- Top-K retrieval (typically **k=3 to 5**)
- `return_source_documents=True` for **citations**

---

## 4. OCI Generative AI Agents

### 4.1 Overview

**OCI Generative AI Agents**: Fully managed service combining **LLMs + intelligent retrieval** for contextual, actionable responses.

**Purpose**: Automate tasks like:
- Booking
- Querying enterprise data
- Summarization
- Multi-step workflows

### 4.2 Core Architecture

```
User Interface (Chatbot/Web/Voice/API)
            ↓
    OCI GenAI Agent
            ↓
    ┌──────┴──────┐
    ↓             ↓
Knowledge Base   Tools/Actions
    ↓             ↓
External Data   External APIs
```

**Key Components**:
- **LLM**: Reasoning and generation
- **RAG**: Retrieval from knowledge base
- **Memory**: Conversation context
- **Tools**: External API calls
- **Feedback Loop**: Improve responses

### 4.3 Key Concepts

| Concept | Definition |
|---------|------------|
| **Generative AI Model** | LLM trained on large data for NLU + NLG |
| **Agent** | Autonomous system = LLM + RAG + Tools |
| **Answerability** | Model responds relevantly to queries |
| **Groundedness** | Responses traceable to data sources |

### 4.4 Data Access Hierarchy

```
Data Store (Where data resides)
    ↓
Data Source (Connection details)
    ↓
Knowledge Base (Vector storage system)
    ↓
Agent (Uses KB for retrieval)
```

### 4.5 Supported Data Sources

| Data Source | Description | File Types | Limits |
|-------------|-------------|------------|--------|
| **OCI Object Storage** | Managed ingestion | PDF, TXT | ≤100MB per file |
| **OCI OpenSearch** | Bring-your-own index | Any | Pre-indexed |
| **Oracle DB 23ai Vector Store** | Custom embeddings | Structured | SQL-based retrieval |

**Object Storage Requirements**:
- Max **1,000 files** per source
- Max **100MB** per file
- Supported: **PDF, TXT**
- Images in PDFs: **Ignored**

### 4.6 Data Ingestion

**Process**: Extract → Transform → Store into knowledge base

**Hybrid Search** = **Lexical + Semantic** search
- **Lexical**: Keyword matching (exact words)
- **Semantic**: Meaning-based (embeddings)
- **Combined**: Higher accuracy

**Ingestion Jobs**:
- Add new documents
- Retry failed ingestions
- Update existing documents
- Cancel running jobs

### 4.7 Additional Features

| Feature | Purpose | Default/Limit |
|---------|---------|---------------|
| **Session** | Maintains context across exchanges | Timeout: 1hr-7d (default: 3,600s) |
| **Endpoint** | Access point for external apps | One per agent |
| **Trace** | Logs full conversation history | For debugging |
| **Citation** | Sources of responses | Transparency |
| **Content Moderation** | Filters harmful content | Input, output, or both |

### 4.8 Database Guidelines (Oracle 23ai)

**Table Structure**:
```sql
CREATE TABLE chunks (
    DOCID VARCHAR2(100),
    body CLOB,
    vector VECTOR(1024, FLOAT32)
);
```

**Requirements**:
- Same **embedding model** for indexing and querying
- Define **retrieval function** (PL/SQL)
- Returns: `DOCID`, `body`, `score`
- Supports: **Cosine similarity** or **Euclidean distance**

**Example Retrieval Function**:
```sql
CREATE FUNCTION vector_search(
    query_vector VECTOR,
    top_k NUMBER
) RETURN SYS_REFCURSOR
AS
    results SYS_REFCURSOR;
BEGIN
    OPEN results FOR
        SELECT DOCID, body, VECTOR_DISTANCE(vector, query_vector, COSINE) as score
        FROM chunks
        ORDER BY score
        FETCH FIRST top_k ROWS ONLY;
    RETURN results;
END;
```

### 4.9 Agent Workflow

```
1. Create Knowledge Base
   → Choose data store (Object Storage, Oracle DB, OpenSearch)

2. Ingest Data
   → Upload PDFs/TXTs or vectorized data

3. Create Agent
   → Define welcome message
   → Select knowledge base
   → Configure model

4. Create Endpoint
   → Configure session timeout
   → Enable moderation, trace, citation

5. Chat & Test
   → Query agent
   → View responses, citations, trace
```

### 4.10 Default Limits

| Resource | Limit |
|----------|-------|
| **Data sources** | 1 per knowledge base |
| **Files** | 1,000 per source |
| **File size** | 100MB each |
| **Session timeout** | 3,600s (default), up to 7 days |

### 4.11 Content Moderation

**Purpose**: Filter harmful content

**Applies To**:
- **Input**: User prompts
- **Output**: Agent responses
- **Both**: Full protection

**Categories**:
- Hate speech
- Violence
- Sexual content
- Self-harm
- Illegal activities

### 4.12 Groundedness vs Hallucination

| Concept | Definition | How to Ensure |
|---------|------------|---------------|
| **Groundedness** | Responses traceable to sources | Use RAG, enable citations |
| **Hallucination** | Invented/incorrect information | Restrict to retrieved context |

**Best Practice**: Use **RAG + Citations** to ensure groundedness.

### 4.13 Agent vs Chatbot

| Feature | Chatbot | Agent |
|---------|---------|-------|
| **Context** | May maintain | ✅ Maintains |
| **External Tools** | ❌ No | ✅ Yes |
| **RAG** | Optional | ✅ Built-in |
| **Reasoning** | Limited | ✅ Advanced |
| **Multi-step** | ❌ No | ✅ Yes |

**Key Difference**: Agents can **call external APIs/tools** during reasoning.

### 4.14 Cost Optimization & Security Considerations

#### Cost Optimization

**Model Selection**:
- Use **smallest model** that meets requirements
- Simple Q&A → Command-R | Complex reasoning → Command-R-Plus

**Fine-tuning Cost**: `Cost = Units × Hourly Rate × Hours`
- Use **T-Few or LoRA** (parameter-efficient)
- Run **pilot jobs** to estimate

**Hosting Cost**: `Monthly Cost = Units × Hourly Rate × 744 hrs`
- Minimum **744 hours/month** (24×7 commitment)
- Use **on-demand inference** for low traffic

**RAG vs Fine-tuning**: Use **RAG first**, fine-tune only if necessary

#### Security & Governance

**IAM**: Dynamic Groups + Policies (Principle of Least Privilege)
```
Allow dynamic-group genai-agents to read objects in compartment knowledge-base
Allow dynamic-group genai-agents to use generative-ai-family in tenancy
```

**Data Privacy**:
- Customer data **never used** to train Oracle's base models
- Encrypted at rest and in transit with **OCI Key Management (Vault)**
- **Isolated** within your tenancy

**Network Security**: **Private Endpoints** within VCN for compliance (healthcare, finance)

**Content Moderation**: Filter harmful content (hate speech, violence, sexual content, self-harm)

**Compliance**: ISO 27001, SOC 1/2/3, GDPR, HIPAA eligible | **NIST AI RMF** governance framework

---

## 5. Quick Reference

### Important Limits & Numbers

| Resource | Limit |
|----------|-------|
| **Command-R-Plus context** | 128k tokens |
| **Embedding input** | 512 tokens |
| **Max embeddings per request** | 96 inputs |
| **Object Storage file size** | 100 MB |
| **Files per data source** | 1,000 |
| **Default session timeout** | 3,600s (1 hour) |
| **Hosting commitment** | 744 hrs/month |
| **GPU sizing (≤13B params)** | 4-8 units |
| **GPU sizing (30-70B params)** | 8-16+ units |

### Model & Approach Selection

| Use Case | Recommended Model/Approach |
|----------|---------------------------|
| Short conversations | Command-R (16k) |
| Long documents | Command-R-Plus (128k) |
| Semantic search | Cohere embed models |
| Multilingual | embed-multilingual |
| Quick experiments | Prompting |
| Dynamic data, citations | RAG |
| Domain-specific, static | Fine-tuning |
| Training from scratch | Never (too expensive) |

### Data Sources

| Source | Managed | File Types | Pre-processing |
|--------|---------|------------|----------------|
| **Object Storage** | Yes | PDF, TXT | Automatic |
| **OpenSearch** | No | Any | You manage |
| **Oracle 23ai** | No | Structured | Custom functions |

---

## 6. Resources & Certification

### Exam Resources
- [1Z0-1127-24 Question Dumps](https://www.scribd.com/document/742863344/1Z0-1127-24-OCI-Generative-AI-Professional)
- [1Z0-1127-25 Cheat Sheet](https://www.linkedin.com/pulse/cheersheet-1z0-1127-25-oracle-cloud-infrastructure-2025-david-edwards-xdqde)

### Key Exam Topics
- Encoder vs Decoder architectures | Prompting techniques (Zero-shot, Few-shot, Chain-of-Thought)
- Cost calculations (Fine-tuning & Hosting) | T-Few fine-tuning method
- RAG pipeline phases | HNSW vs IVF indexes | Cosine vs Dot Product similarity
- Agent vs Chatbot differences | Hybrid search (Lexical + Semantic)
- Groundedness & hallucination mitigation | IAM policies for Agents
- Private endpoints for compliance | Frequency vs Presence Penalty
- Cluster types (Large Meta Dedicated for Llama) | OCI Key Management

### Certification Badge

![OCI Generative AI Professional Certification](/learning-notes/images/eCertificate.png)

---

*Last updated: 2025-10-22*
