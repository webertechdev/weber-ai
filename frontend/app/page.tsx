"use client";

import { useState, useRef, useEffect } from "react";

import { Send } from "lucide-react";

import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

import { Prism as SyntaxHighlighter } from "react-syntax-highlighter";

import { oneDark } from "react-syntax-highlighter/dist/esm/styles/prism";

export default function Home() {

  const [message, setMessage] = useState("");

  const [messages, setMessages] = useState<any[]>([]);

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

          setConversationId(Number(savedId));

          const response = await fetch(
            `http://127.0.0.1:8000/api/messages/${savedId}`
          );

          const data = await response.json();

          if (Array.isArray(data)) {
            setMessages(data);
          }

        } else {

          // CREATE NEW CHAT
          const response = await fetch(
            "http://127.0.0.1:8000/api/conversations",
            {
              method: "POST"
            }
          );

          const data = await response.json();

          localStorage.setItem(
            "conversation_id",
            String(data.id)
          );

          setConversationId(data.id);

        }

      } catch (error) {

        console.error("Failed loading chat:", error);

      }

    };

    initializeChat();

  }, []);

  // AUTO SCROLL
  useEffect(() => {

    bottomRef.current?.scrollIntoView({
      behavior: "smooth"
    });

  }, [messages]);

  // SEND MESSAGE
  const sendMessage = async () => {

    if (!message.trim()) return;

    if (!conversationId) return;

    const currentMessage = message;

    const userMessage = {
      role: "user",
      content: currentMessage
    };

    const updatedMessages = [
      ...messages,
      userMessage
    ];

    setMessages(updatedMessages);

    setMessage("");

    setLoading(true);

    try {

      const response = await fetch(
        "http://127.0.0.1:8000/api/stream",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            message: currentMessage,
            messages: updatedMessages,
            conversation_id: conversationId
          })
        }
      );

      if (!response.body) return;

      const reader = response.body.getReader();

      const decoder = new TextDecoder();

      let aiResponse = "";

      // EMPTY ASSISTANT MESSAGE
      setMessages((prev) => [
        ...prev,
        {
          role: "assistant",
          content: ""
        }
      ]);

      while (true) {

        const { done, value } = await reader.read();

        if (done) break;

        const chunk = decoder.decode(value);

        aiResponse += chunk;

        setMessages((prev) => {

          const updated = [...prev];

          updated[updated.length - 1] = {
            role: "assistant",
            content: aiResponse
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
          content: "Error connecting to WEBARE AI backend."
        }
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
      <div className="flex-1 overflow-y-auto p-6 space-y-6">

        {messages.map((msg, index) => (

          <div
            key={index}
            className={`max-w-4xl rounded-2xl p-5 whitespace-pre-wrap ${
              msg.role === "user"
                ? "ml-auto bg-blue-600"
                : "bg-zinc-900 border border-zinc-800"
            }`}
          >

            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              components={{
                code({ inline, className, children, ...props }: any) {

                  const match = /language-(\w+)/.exec(className || "");

                  return !inline && match ? (
                    <SyntaxHighlighter
                      style={oneDark}
                      language={match[1]}
                      PreTag="div"
                    >
                      {String(children).replace(/\n$/, "")}
                    </SyntaxHighlighter>
                  ) : (
                    <code
                      className="bg-zinc-800 px-1 rounded"
                      {...props}
                    >
                      {children}
                    </code>
                  );

                }
              }}
            >
              {msg.content}
            </ReactMarkdown>

          </div>

        ))}

        {/* LOADING */}
        {loading && (

          <div className="bg-zinc-900 border border-zinc-800 rounded-2xl p-5 max-w-4xl">

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
            onChange={(e) => setMessage(e.target.value)}
            placeholder="Ask WEBARE AI anything..."
            className="flex-1 rounded-xl bg-zinc-900 border border-zinc-800 p-4 outline-none"
            onKeyDown={(e) => {

              if (e.key === "Enter") {

                sendMessage();

              }

            }}
          />

          <button
            onClick={sendMessage}
            className="rounded-xl bg-blue-600 px-6 hover:bg-blue-700 transition"
          >
            <Send size={20} />
          </button>

        </div>

      </div>

    </main>

  );

}