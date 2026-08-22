"use client";

import { useEffect, useRef, useState } from "react";

import { Send } from "lucide-react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";
import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";

const API_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";

type Message = {
  role: "user" | "assistant";
  content: string;
};

export default function Home() {
  const [message, setMessage] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [conversationId, setConversationId] = useState<number | null>(null);
  const [loading, setLoading] = useState(false);

  const bottomRef = useRef<HTMLDivElement | null>(null);

  // LOAD CHAT
  useEffect(() => {
    const initializeChat = async () => {
      try {
        const savedId = localStorage.getItem("conversation_id");

        // LOAD EXISTING CHAT
        if (savedId) {
          const id = Number(savedId);

          setConversationId(id);

          const response = await fetch(
            `${API_URL}/api/messages/${savedId}`
          );

          if (!response.ok) {
            throw new Error(
              `Failed to load messages: ${response.status}`
            );
          }

          const data = await response.json();

          if (Array.isArray(data)) {
            setMessages(data);
          }

          return;
        }

        // CREATE NEW CHAT
        const response = await fetch(
          `${API_URL}/api/conversations`,
          {
            method: "POST",
          }
        );

        if (!response.ok) {
          throw new Error(
            `Failed to create conversation: ${response.status}`
          );
        }

        const data = await response.json();

        localStorage.setItem(
          "conversation_id",
          String(data.id)
        );

        setConversationId(data.id);
      } catch (error) {
        console.error("Failed loading chat:", error);
      }
    };

    initializeChat();
  }, []);

  // AUTO SCROLL
  useEffect(() => {
    bottomRef.current?.scrollIntoView({
      behavior: "smooth",
    });
  }, [messages]);

  // SEND MESSAGE
  const sendMessage = async () => {
    if (!message.trim() || !conversationId || loading) {
      return;
    }

    const currentMessage = message.trim();

    const userMessage: Message = {
      role: "user",
      content: currentMessage,
    };

    const updatedMessages = [
      ...messages,
      userMessage,
    ];

    setMessages(updatedMessages);
    setMessage("");
    setLoading(true);

    try {
      const response = await fetch(
        `${API_URL}/api/stream`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            message: currentMessage,
            messages: updatedMessages,
            conversation_id: conversationId,
          }),
        }
      );

      if (!response.ok) {
        throw new Error(
          `Backend returned ${response.status}`
        );
      }

      if (!response.body) {
        throw new Error("No response body received.");
      }

      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      let aiResponse = "";

      // EMPTY ASSISTANT MESSAGE
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: "",
        },
      ]);

      while (true) {
        const { done, value } = await reader.read();

        if (done) {
          break;
        }

        const chunk = decoder.decode(value, {
          stream: true,
        });

        aiResponse += chunk;

        setMessages((prev) => {
          const updated = [...prev];

          updated[updated.length - 1] = {
            role: "assistant",
            content: aiResponse,
          };

          return updated;
        });
      }
    } catch (error) {
      console.error("Failed sending message:", error);

      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content:
            "Error connecting to WEBARE AI backend.",
        },
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="flex h-screen flex-col bg-black text-white">
      {/* HEADER */}
      <div className="border-b border-zinc-800 p-4">
        <h1 className="text-2xl font-bold">
          WEBARE AI
        </h1>

        <p className="text-sm text-zinc-400">
          Corporate Intelligence Platform
        </p>
      </div>

      {/* CHAT AREA */}
      <div className="flex-1 space-y-6 overflow-y-auto p-6">
        {messages.map((msg, index) => (
          <div
            key={index}
            className={`max-w-4xl rounded-2xl border p-5 ${
              msg.role === "user"
                ? "ml-auto border-blue-600 bg-blue-600"
                : "border-zinc-800 bg-zinc-900"
            }`}
          >
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                code({ children, className, ...props }) {
                  const match =
                    /language-(\w+)/.exec(
                      className || ""
                    );

                  return match ? (
                    <SyntaxHighlighter
                      style={oneDark}
                      language={match[1]}
                      PreTag="div"
                    >
                      {String(children).replace(
                        /\n$/,
                        ""
                      )}
                    </SyntaxHighlighter>
                  ) : (
                    <code
                      className="rounded bg-zinc-800 px-1"
                      {...props}
                    >
                      {children}
                    </code>
                  );
                },
              }}
            >
              {msg.content}
            </ReactMarkdown>
          </div>
        ))}

        {/* LOADING */}
        {loading && (
          <div className="max-w-4xl rounded-2xl border border-zinc-800 bg-zinc-900 p-5">
            <div className="animate-pulse">
              WEBARE AI is thinking...
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* INPUT */}
      <div className="border-t border-zinc-800 p-4">
        <div className="flex gap-3">
          <input
            value={message}
            onChange={(e) =>
              setMessage(e.target.value)
            }
            placeholder="Ask WEBARE AI anything..."
            className="flex-1 rounded-xl border border-zinc-800 bg-zinc-900 p-4 outline-none"
            disabled={loading}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
              }
            }}
          />

          <button
            onClick={sendMessage}
            disabled={loading}
            className="rounded-xl bg-blue-600 px-6 transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Send size={20} />
          </button>
        </div>
      </div>
    </main>
  );
}
