标题修改为：Envoix: A Hybrid Adaptive Platform for Secure End-to-End File Transfer

微调第二页下面的排布，尽可能一行一行排列而没有换行，同时也不要有重复

第七页，删除左边表格，删除email 以及无用的话，只保留一个链接

第八页，微调表格上下距离，使其离下边界远一点

第14-17页：替换为\section{Competitor Analysis}
% ================================================================

\begin{frame}{Market Overview}
  \begin{block}{The Fundamental Gap}
    Existing systems typically optimize for \textbf{exactly one transport pathway}. No single consumer app combines all approaches into a unified, adaptive experience.
  \end{block}

  \vspace{0.5em}

  \begin{columns}[c]
    \column{0.2\textwidth}
    \centering\small\textbf{Cloud Storage}\\[0.3em]
    \footnotesize Google Drive\\iCloud · Dropbox
    \column{0.2\textwidth}
    \centering\small\textbf{Messaging Apps}\\[0.3em]
    \footnotesize WeChat\\WhatsApp · Telegram
    \column{0.2\textwidth}
    \centering\small\textbf{LAN}\\[0.3em]
    \footnotesize AirDrop\\Nearby Share
    \column{0.2\textwidth}
    \centering\small\textbf{Internet P2P}\\[0.3em]
    \footnotesize BitTorrent\\Syncthing
    \column{0.2\textwidth}
    \centering\small\textbf{PAKE Transfer}\\[0.3em]
    \footnotesize Magic Wormhole\\croc
  \end{columns}

  \vspace{0.8em}
  \centering\textbf{Competitors analyzed:} Google Drive · WeChat · AirDrop · BitTorrent · croc
\end{frame}

\begin{frame}{Competitor Profiles (1/2)}

\vspace{-2.0em}

\small
\setlength{\itemsep}{0em}
\linespread{0.9}\selectfont

\begin{columns}[t]

\column{0.4\textwidth}

\begin{block}{Google Drive --- Cloud Storage}
\begin{itemize}
  \item[\faPlus] Persistent storage
  \item[\faPlus] Cross-device sync
  \item[\faPlus] 15 GB free storage
  \item[\faPlus] No recipient installation
  \item[\faPlus] Fast transfer
  \item[\faMinus] Double bandwidth usage
  \item[\faMinus] Metadata leakage
  \item[\faMinus] Subscription pressure
  \item[\faMinus] Poor for transient transfer
  \item[\faMinus] Privacy concerns
\end{itemize}
\end{block}

\column{0.4\textwidth}

\begin{block}{WeChat --- Messaging App}
\begin{itemize}
  \item[\faPlus] 1.3B+ users
  \item[\faPlus] Already widely used
  \item[\faPlus] Fast and convenient
  \item[\faMinus] 1 GB file limit
  \item[\faMinus] Aggressive compression
  \item[\faMinus] Multiple local copies
  \item[\faMinus] No persistent storage
  \item[\faMinus] Ecosystem lock-in
  \item[\faMinus] Surveillance/privacy risks
\end{itemize}
\end{block}

\end{columns}
\end{frame}

\begin{frame}{Competitor Profiles (2/2)}

\vspace{-2.0em}

\small
\setlength{\itemsep}{0em}
\linespread{0.9}\selectfont
\begin{columns}[t]

\column{0.34\textwidth}

\begin{block}{AirDrop --- LAN}
\begin{itemize}
  \item[\faPlus] Bluetooth + Wi-Fi Direct
  \item[\faPlus] No account required
  \item[\faPlus] No internet required
  \item[\faPlus] Seamless Apple UX
  \item[\faMinus] Apple-only
  \item[\faMinus] Proximity-only
  \item[\faMinus] No remote fallback
  \item[\faMinus] Discovery may leak info
\end{itemize}
\end{block}

\column{0.33\textwidth}

\begin{block}{BitTorrent --- Internet P2P}
\begin{itemize}
  \item[\faPlus] Cross-platform
  \item[\faPlus] Widely used
  \item[\faPlus] Fast P2P transfer
  \item[\faPlus] Secure transfer
  \item[\faMinus] Optimized for many peers
  \item[\faMinus] Weak in small networks
\end{itemize}
\end{block}

\column{0.33\textwidth}

\begin{block}{croc --- PAKE Transfer}
\begin{itemize}
  \item[\faPlus] SPAKE2 cryptographic model
  \item[\faPlus] Relay stores no plaintext
  \item[\faPlus] Resistant to offline attack
  \item[\faPlus] Open-source
  \item[\faPlus] Closest arch to Envoix
  \item[\faMinus] Desktop CLI-only
  \item[\faMinus] No LAN fast path
  \item[\faMinus] All traffic via relay
\end{itemize}
\end{block}

\end{columns}

\end{frame}


\linespread{1.0}\selectfont
\small
\begin{frame}{Comparison Table}

\vspace{-0.5em}

\scriptsize
\linespread{0.95}\selectfont

\centering

\resizebox{\textwidth}{!}{%
\begin{tabular}{lcccccc}
\toprule
\textbf{Feature} &
\textbf{Google Drive} &
\textbf{WeChat} &
\textbf{AirDrop} &
\textbf{BitTorrent} &
\textbf{croc} &
\textbf{Envoix} \\
\midrule

Cross-platform
& \checkmark
& Partial
& $\times$
& \checkmark
& \checkmark
& \textbf{\checkmark} \\

LAN / local transfer
& $\times$
& $\times$
& \checkmark
& $\times$
& $\times$
& \textbf{\checkmark} \\

Internet / relay
& \checkmark
& \checkmark
& $\times$
& $\times$
& \checkmark
& \textbf{\checkmark} \\

P2P transfer
& $\times$
& $\times$
& \checkmark
& \checkmark
& $\times$
& \textbf{\checkmark} \\

\rowcolor{cprimary!15}
Auto-routing
& $\times$
& $\times$
& $\times$
& $\times$
& $\times$
& \textbf{\checkmark} \\

\rowcolor{cprimary!15}
Adaptive LAN + relay
& $\times$
& $\times$
& $\times$
& $\times$
& $\times$
& \textbf{\checkmark} \\

\rowcolor{cprimary!15}
E2EE (all modes)
& $\times$
& $\times$
& Partial
& Partial
& \checkmark
& \textbf{\checkmark} \\

No account required
& \checkmark
& $\times$
& \checkmark
& \checkmark
& \checkmark
& \textbf{\checkmark} \\

No ecosystem lock-in
& \checkmark
& $\times$
& $\times$
& \checkmark
& \checkmark
& \textbf{\checkmark} \\

Mobile app
& \checkmark
& \checkmark
& \checkmark
& Partial
& $\times$
& \textbf{\checkmark} \\

Resume on failure
& Partial
& $\times$
& $\times$
& Partial
& $\times$
& \textbf{\checkmark} \\

Open-source
& $\times$
& $\times$
& $\times$
& \checkmark
& \checkmark
& \textbf{\checkmark} \\

\bottomrule
\end{tabular}%
}

\end{frame}

% ================================================================
% \section{Technical Differentiation}
% % ================================================================

% \begin{frame}[shrink=22]{Intelligent Transfer Routing Engine}
%   \begin{block}{Core Insight}
%     Every competitor optimizes a \textbf{single transfer modality} and asks users to manage the rest manually.\\
%     Envoix treats the protocol stack as a \textbf{scored decision}, not a user configuration.
%   \end{block}

%   \vspace{0.5em}

%   \textbf{Priority chain (probed automatically after pairing):}

%   \vspace{0.3em}

%   \begin{enumerate}
%     \item \textbf{mDNS-based LAN} --- lowest latency, highest throughput, no internet dependency
%     \item \textbf{IPv6 direct P2P} --- increasingly viable on campus and carrier networks
%     \item \textbf{QUIC/UDP hole-punching} --- rendezvous-assisted NAT traversal; no file content on relay
%     \item \textbf{Centralized relay fallback} --- guarantees delivery under any condition; relay handles ciphertext only
%   \end{enumerate}

%   \vspace{0.5em}
%   \textit{The user sees one consistent interaction: \textbf{pair, send, done}. Path degradation triggers silent fallback.}
% \end{frame}

% \begin{frame}[shrink=33]{Security Model \& Encrypted Chat}
%   \begin{columns}[t]
%     \column{0.5\textwidth}
%     \begin{block}{Uniform Security Across All Modes}
%       \begin{itemize}
%         \item QR / short-code handshake establishes a session key (SPAKE2)
%         \item All file chunks and chat messages encrypted \textbf{before leaving the device}
%         \item Relay server never sees plaintext
%         \item Relay-cached messages cleared weekly
%       \end{itemize}
%     \end{block}
%     \column{0.5\textwidth}
%     \begin{block}{Encrypted Chat Layer}
%       \begin{itemize}
%         \item \textbf{No competitor} integrates encrypted chat alongside file transfer
%         \item The conversation about a file is as private as the file itself
%         \item Same E2EE session --- no context leakage
%       \end{itemize}
%     \end{block}
%   \end{columns}

%   \vspace{1em}

%   \begin{alertblock}{Why This is Hard to Copy}
%     The routing engine cannot be added incrementally to a single-modality app. Competitors would need to simultaneously rebuild their network layer, session model, and security architecture --- at odds with their current business models and architectural philosophy.
%   \end{alertblock}
% \end{frame}

% % ================================================================
% % Closing
% % ================================================================
% \begin{frame}{Summary}
%   \begin{columns}[c]
%     \column{0.5\textwidth}
%     \begin{block}{What We Bring}
%       \begin{itemize}
%         \item Intelligent multi-protocol routing engine
%         \item Uniform E2EE across LAN, P2P, and relay
%         \item Integrated encrypted chat
%         \item No account, no ads, no decision cost
%       \end{itemize}
%     \end{block}
%     \column{0.5\textwidth}
%     \begin{block}{Next Steps}
%       \begin{itemize}
%         \item Conduct user interviews (10--15 participants)
%         \item Synthesize pain points \& refine problem framing
%         \item Prototype routing engine core
%         \item Validate pairing UX with paper prototypes
%       \end{itemize}
%     \end{block}
%   \end{columns}

%   \vspace{1.5em}

%   \centering\Large\textbf{Thank you --- Questions?}
% \end{frame}

% \appendix
% % \section{User Interview Questionnaire}

% \begin{frame}[shrink=8]{Interview Design --- Participants \& Venue}
%   \begin{columns}[t]
%     \column{0.5\textwidth}
%     \begin{block}{How We Find Interviewees}
%       \begin{itemize}
%         \item SJTU engineering/CS communities
%         \item GitHub discussions, V2EX, WeChat tech groups
%         \item Screening: regularly transfer files across multiple devices/OS, and have encountered at least one of: size limits, incompatibility, network failure, privacy concerns
%         \item \textbf{Avoid friends/family} --- reduce social desirability bias
%       \end{itemize}
%     \end{block}
%     \column{0.5\textwidth}
%     \begin{block}{Venue \& Session Structure}
%       \begin{itemize}
%         \item Remote via Tencent Meeting / Zoom
%         \item 10--20 min per session
%         \item One interviewer + one note-taker
%         \item Recorded with consent
%       \end{itemize}
%       \vspace{0.5em}
%       \begin{tabular}{ll}
%         0--5 min  & Warm-up, device context \\
%         5--15 min & Pain stories, failure scenarios \\
%         15--20 min & Ideal workflow, retention \\
%       \end{tabular}
%     \end{block}
%   \end{columns}
% \end{frame}

% \begin{frame}{Theme 1: Device Context \& Current Behavior}
%   \textit{Goal: Establish devices/platforms used and current tools, without leading toward any product concept.}

%   \vspace{0.8em}

%   \begin{enumerate}
%     \item[\textbf{Q1}] Walk me through the devices you use daily and how often they need to share files with each other.
%     \item[\textbf{Q2}] Think back to the last few weeks --- what triggered your need to send a file, and to whom?
%     \item[\textbf{Q3}] What apps or methods do you normally reach for? How did you settle on those tools?
%     \item[\textbf{Q4}] When you're about to send a file, what goes through your head before deciding which tool to use?
%   \end{enumerate}
% \end{frame}

% \begin{frame}{Theme 2: Pain Points \& Failure Stories}
%   \textit{Goal: Surface real breakdown moments, workarounds, and emotional friction.}

%   \vspace{0.8em}

%   \begin{enumerate}
%     \item[\textbf{Q5}] Walk me through the last time you sent a large file --- from the moment you decided to send it to delivery.
%     \item[\textbf{Q6}] Has your usual method ever just stopped working? What happened, and what did you do instead?
%     \item[\textbf{Q7}] When transferring between iPhone and Android, or phone and a different-OS computer, how do you handle that?
%     \item[\textbf{Q8}] Describe a time when security/privacy crossed your mind during a file transfer. Did it change your behavior?
%     \item[\textbf{Q9}] What does it feel like when a transfer fails or arrives corrupted? Tell me about a specific moment.
%   \end{enumerate}
% \end{frame}

% \begin{frame}{Theme 3: Motivations, Ideals \& Accepted Friction}
%   \textit{Goal: Understand retention drivers, unarticulated needs, and normalized workarounds.}

%   \vspace{0.8em}

%   \begin{enumerate}
%     \item[\textbf{Q10}] When a file transfer tool works really well, what makes you keep coming back to it?
%     \item[\textbf{Q11}] Describe your ideal file-sending experience for a scenario that comes up regularly for you.
%     \item[\textbf{Q12}] What frustrations have you accepted as ``the way file transfer works'' --- things you've stopped trying to fix?
%   \end{enumerate}
% \end{frame}



