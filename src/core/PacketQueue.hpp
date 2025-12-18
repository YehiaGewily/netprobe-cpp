#pragma once

#include "PacketData.hpp"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <optional>

namespace core {

    class PacketQueue {
    public:
        // Push a packet into the queue
        void push(const PacketData& packet) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_queue.push(packet);
            }
            m_cv.notify_one();
        }

        // Push a packet (move semantics)
        void push(PacketData&& packet) {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
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

        void clear() {
            std::lock_guard<std::mutex> lock(m_mutex);
            std::queue<PacketData> empty;
            std::swap(m_queue, empty);
        }

    private:
        std::queue<PacketData> m_queue;
        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
    };

} // namespace core
