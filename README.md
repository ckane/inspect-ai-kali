# Inspect AI Eval Demonstration

Some demonstrations of using [Inspect AI](https://inspect.aisi.org.uk/) for doing model evaluations. Right now it
builds and initializes a Kali Linux docker image for the agent(s) under benchmark to
use, as an MCP-exposed tool. There are also victim containers that are created which
the agents must attempt to assess vulnerabilities of and then crack into. The setup
is largely flag capturing, but there's no reason why the prompting cannot be modified
for the agents to achieve some other objective as the goal.

I have primarily tested using Azure OpenAI and [llama.cpp](https://github.com/ggml-org/llama.cpp)
hosted models.

So, with the latest Azure OpenAI interface, you may create a new env file:

```sh
cat > .env.azure.gpt54mini << END
AZGPT_ENDPOINT=https://your-resource-name.cognitiveservices.azure.com/openai/v1
AZGPT_KEY=YourServiceKey
END
```

And then run the benchmark with:

```sh
uv run --env-file .env.azure.gpt54mini   \
  inspect eval testtask.py               \
  --model openai-api/azgpt/gpt-5.4-nano  \
  -M strict_tools=false
```

The final `-< strict_tools=false` parameter will address an issue where [Inspect AI](https://inspect.aisi.org.uk/)
by default may set the tool schema to "strict", but the MCP servers do not always
adhere to this.
