module Acl9
  module Dsl
    def expression_join(parts, with)
      parts.map { |p| "(#{p})" } * with
    end

    def andify(parts)
      expression_join(parts, ' && ')
    end

    def orify(parts)
      expression_join(parts, ' || ')
    end

    module_function :expression_join, :andify, :orify

    # A class that represents :if/:unless rule conditions
    class Condition < Struct.new(:method, :negate)
      # @return [String] Condition-checking expression (which will return +true+ if condition is met)
      # @param [Generator] gen Generator
      def expression(gen)
        m = gen.method_call(method)
        negate ? "!#{m}" : m
      end
    end

    # A class that represents :to/:except action checks
    class ActionCheck < Struct.new(:actions, :negate)
      # @return [String] Action-checking expression (which will return +true+ if current action should
      # be checked)
      # @param [Generator] gen Generator
      def expression(gen)
        m = case actions.size
            when 0 then "true"
            when 1 then "#{gen.current_action} == '#{actions.first}'"
            else
              set_of_actions = "Set.new([" + actions.map { |act| "'#{act}'"}.join(',')  + "])"

              "#{set_of_actions}.include?(#{_action_ref})"
            end

        negate ? "!#{m}" : m
      end
    end

    LOGGED_IN = false
    ANONYMOUS = nil
    ALL       = true

    # A class that represents access control rule
    class Rule < Struct.new(:roles, :object, :action_check, :condition)
      # @return [String] Rule-matching expression (which will return +true+ if rule matched)
      # @param [Generator] gen Generator
      def expression(gen)
        role_checks = roles.map do |role|
          case role
          when ANONYMOUS then  "#{gen.subject}.nil?"
          when LOGGED_IN then "!#{gen.subject}.nil?"
          when ALL       then "true"
          else
            "!#{gen.subject}.nil? &&
              #{gen.subject}.has_role?('#{role.to_s.singularize}', #{object_expr(gen)})"
          end
        end.uniq

        role_checks = nil if role_checks == ['true']

        Dsl.andify([
                    action_check && action_check.expression(gen),
                    condition && condition.expression(gen),
                    role_checks && Dsl.orify(role_checks)
                   ].compact)
      end

      protected

      def object_expr(gen)
        case object
        when Class
          object.to_s
        when Symbol
          gen.object(object)
        when nil
          "nil"
        else
          raise
        end
      end
    end

    class AllowRule < Rule
      def allow?; true  end
      def deny?;  false end
    end

    class DenyRule < Rule
      def allow?; false end
      def deny?;  true  end
    end

    # DSL processor
    class Processor
      attr_reader :rules

      def initialize
        @default_action = nil
        @rules = []
      end

      # Populate rules from given block
      def acl_block!(&block)
        instance_eval(&block)
      end

      # @return [Symbol] default action (:allow or :deny)
      def default_action
        @default_action.nil? ? :deny : @default_action
      end

      def expression(gen)
        allow_rules = rules.select { |rule| rule.allow? }
        deny_rules  = rules.select { |rule| rule.deny? }

        allowed_expr = if allow_rules.size > 0
                         Dsl.orify(allow_rules.map { |rule| rule.expression(gen) })
                       else
                         "false"
                       end

        not_denied_expr = if deny_rules.size > 0
                            "!" + Dsl.orify(deny_rules.map { |rule| rule.expression(gen) })
                          else
                            "true"
                          end

        Dsl.send((default_action == :deny ? :andify : :orify), [allowed_expr, not_denied_expr])
      end

      protected

      def default(default_action)
        raise ArgumentError, "default can only be called once in access_control block" if @default_action

        unless [:allow, :deny].include? default_action
          raise ArgumentError, "invalid value for default (can be :allow or :deny)"
        end

        @default_action = default_action
      end

      def allow(*args)
        # ...
      end

      def deny(*args)
        # ...
      end

      def actions(*args, &block)
        # ...
      end

      alias action actions

      def logged_in; LOGGED_IN end
      def anonymous; ANONYMOUS end
      def all;       ALL       end

      alias everyone all
      alias everybody all
      alias anyone all
    end
  end
end
