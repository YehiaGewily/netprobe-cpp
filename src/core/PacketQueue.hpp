#pragma once

#include "PacketData.hpp"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>
#include <cstddef>

namespace core {

    class PacketQueue {
    public:
        explicit PacketQueue(size_t maxSize = 50'000)
            : m_maxSize(maxSize > 0 ? maxSize : 1) {}

        // Push a packet into the queue
        void push(const PacketData& packet) {
            push(PacketData(packet));
        }

        // Push a packet (move semantics).
        // When full, drop the OLDEST packet (FIFO eviction) rather than the new one.
        // Rationale: NetProbe is an analyzer, not a forensic recorder — if the UI
        // can't keep up we'd rather show the user the most recent traffic than
        // stall the capture thread or hold onto stale data. The dropped count is
        // surfaced in the UI so users can see when the queue is overrun.
        void push(PacketData&& packet) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                if (m_queue.size() >= m_maxSize) {
                    m_queue.pop();
                    ++m_droppedPackets;
                }
                m_queue.push(std::move(packet));
            }
            m_cv.notify_one();
        }

        // Blocking pop - waits until a packet is available
        PacketData pop() {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_cv.wait(lock, [this] { return !m_queue.empty(); });
            PacketData packet = std::move(m_queue.front());
            m_queue.pop();
            return packet;
        }

        // Non-blocking pop - returns std::nullopt if empty
        std::optional<PacketData> try_pop() {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_queue.empty()) {
                return std::nullopt;
            }
            PacketData packet = std::move(m_queue.front());
            m_queue.pop();
            return packet;
        }

        size_t size() const {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_queue.size();
        }

        bool empty() const {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_queue.empty();
        }

        size_t droppedPackets() const {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_droppedPackets;
        }

        void clear() {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::queue<PacketData> empty;
            std::swap(m_queue, empty);
        }

    private:
        std::queue<PacketData> m_queue;
        size_t m_maxSize;
        size_t m_droppedPackets = 0;
        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
    };

} // namespace core
