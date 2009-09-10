module Acl9
  module Dsl
    def expression_join(parts, with)
      # TODO: remove excessful parentheses
      parts.compact.map { |p| "(#{p})" } * with
    end

    # Construct AND expression from parts
    #
    # @param [Array] parts Array of expressions
    def andify(parts)
      # TODO: remove (true)
      expression_join(parts, ' && ')
    end

    # Construct OR expression from parts
    #
    # @param [Array] parts Array of expressions
    def orify(parts)
      # TODO: remove (false)
      expression_join(parts, ' || ')
    end

    module_function :expression_join, :andify, :orify

    # :if or :unless rule conditions
    class Condition < Struct.new(:method, :negate)
      # @return [String] Condition-checking expression (which will return +true+ if condition is met). Will return +nil+ if method is +nil+.
      # @param [Generator] gen Generator
      def expression(gen)
        if method
          m = gen.method_call(method)
          negate ? "!#{m}" : m
        end
      end
    end

    # Combined :if and :unless condition
    #
    # Sorta IF && !UNLESS
    class DoubleCondition
      # @param [Symbol] _if Method that should return trueish value for a rule to get checked
      # @param [Symbol] _unless Method that should return +false+ or +nil+ for a rule to get checked
      def initialize(_if, _unless)
        @if = Condition.new(_if, false)
        @unless = Condition.new(_unless, true)
      end

      # @return [String] Condition-checking expression. Will return +nil+ when both IF and UNLESS conditions are not specified.
      # @param [Generator] gen Generator
      def expression(gen)
        res = Dsl.andify [@if.expression(gen), @unless.expression(gen)]

        res.empty? ? nil : res
      end
    end

    # :to/:except action checks
    class ActionCheck < Struct.new(:actions, :negate)
      def initialize(*args)
        super

        self.actions = [actions] unless actions.is_a? Array
      end

      # @return [String] Action-checking expression (which will return +true+ if current action should
      # be checked)
      # @param [Generator] gen Generator
      def expression(gen)
        m = case actions.size
            when 0 then "true"
            when 1 then "#{gen.current_action} == '#{actions.first}'"
            else
              set_of_actions = "Set.new([" + actions.map { |act| "'#{act}'"}.join(',')  + "])"

              "#{set_of_actions}.include?(#{gen.current_action})"
            end

        negate ? "!#{m}" : m
      end
    end

    LOGGED_IN = false
    ANONYMOUS = nil
    ALL       = true

    # Access control rule
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

        Dsl.andify([
                    action_check && action_check.expression(gen),
                    condition && condition.expression(gen),
                    role_checks && Dsl.orify(role_checks)
                   ])
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

    # Allow rule
    class AllowRule < Rule
      def allow?; true  end
      def deny?;  false end
    end

    # Deny rule
    class DenyRule < Rule
      def allow?; false end
      def deny?;  true  end
    end

    # DSL processor
    class Processor
      # Array of rules
      attr_reader :rules

      def initialize
        @default_action = nil
        @rules = []
      end

      # Populate {#rules} using given block
      #
      # @yield Block with ACL instructions
      # @see #default
      # @see #allow
      # @see #deny
      def acl_block!(&block)
        instance_eval(&block)
      end

      # Returns default action
      #
      # @return [Symbol] default action (:allow or :deny)
      # @see #default
      def default_action
        @default_action.nil? ? :deny : @default_action
      end

      # Translate {#rules} into Ruby expression, taking {#default_action} into consideration
      #
      # @return [String] Ruby expression (which will return +true+ if access allowed)
      # @see #rules
      # @see #default
      # @see #default_action
      def expression(gen)
        allow_rules = rules.select { |rule| rule.allow? }
        deny_rules  = rules.select { |rule| rule.deny? }

        allowed_expr = if allow_rules.size > 0
                         Dsl.orify(allow_rules.map { |rule| rule.expression(gen) })
                       else
                         "false"
                       end

        not_denied_expr = if deny_rules.size > 0
                            "!(#{Dsl.orify(deny_rules.map { |rule| rule.expression(gen) })})"
                          else
                            "true"
                          end

        Dsl.send((default_action == :deny ? :andify : :orify), [allowed_expr, not_denied_expr])
      end

      # Set default allow or default deny.
      #
      # There are two modes: default allow and default deny. The "default" case
      # occurs when neither of the rules matched.
      #
      # Default deny mode is used you don't call {#default} at all.
      #
      # @param default_action [Symbol] :allow or :deny
      def default(default_action)
        raise ArgumentError, "default can only be called once in access_control block" if @default_action

        unless [:allow, :deny].include? default_action
          raise ArgumentError, "invalid value for default (can be :allow or :deny)"
        end

        @default_action = default_action
      end

      # Add an allow rule
      #
      # This creates a record in the {#rules rules} table. Rule states that
      # users with specified roles (or pseudoroles, such as {#all all},
      # {#logged_in logged_in} or {#anonymous anonymous}) are allowed into
      # certain actions of controller.
      #
      # Roles are given as positional arguments. For example, here users with
      # 'admin' and 'manager' roles are allowed:
      #
      #   allow :admin, :manager
      #
      # Acl9 supports the notion of object roles, i.e. roles tied to a specific
      # object. E.g. a 'project' might have 'manager' and 'member' roles. To
      # check an object role within the rule you should use one of the
      # preposition options (see below).
      #
      #   allow :manager, :of => :project
      #   allow :responsible, :for => :result
      #
      # Here +project+ and +result+ will be taken from controller instance
      # variables (or from optional variables hash in the case of query method,
      # see {Acl9::ControllerExtensions::ClassMethods#access_control
      # access_control}).
      #
      # All role checks are done with {Acl9::ModelExtensions::Subject#has_role?
      # user.has_role?} call, and the object will be passed as the second
      # parameter, like this:
      #
      #   current_user.has_role?('manager', @project)
      #   current_user.has_role?('responsible', @result)
      #
      # Another possibility is a class role, i.e. role tied to a class.
      #
      #   allow :employed, :by => FBI
      #
      # This will make
      #
      #   current_user.has_role?('manager', FBI)
      #
      # in the code.
      #
      # If two (or more) roles are specified along with a preposition option, they are both
      # treated as object (or class) roles:
      #
      #   allow :devil, :son, :of => God
      #   # same as
      #   allow :devil, :of => God
      #   allow :son,   :of => God
      #   # NOT this:
      #   # allow :devil
      #   # allow :son, :of => God
      #
      # Preposition options are ignored for pseudoroles.
      #
      # A rule may have limited action scope, in which case it will be
      # considered only for specified controller actions. Scope is specified
      # with +:to+ and +:except+ options.
      #
      #   allow all, :to => [:index, :show]    # only index and show allowed
      #   allow :ripper, :to => :destroy       # only destroy allowed
      #   allow :manager, :except => :destroy  # anything but destroy action is allowed
      #
      # Rule may also be conditional, i.e. considered only when certain condition is met.
      #
      #   allow all, :to => :index, :if => :users_welcome?
      #
      #
      # @overload allow(*roles, opts={})
      #   @param [Array] roles A list of roles. Each role is either a Symbol (+:admin+, +:manager+, etc.),
      #     a String ('admin', 'manager') or a pseudorole  (+all+, +logged_in+ or +anonymous+.
      #   @param [Hash] options Rule options
      #   @option opts [Symbol] :if Method that should return trueish value for the rule to be considered
      #   @option opts [Symbol] :unless Method that should return +nil+ or +false+ for the rule to be considered
      #   @option opts [Array<Symbol, String>, Symbol, String] :to Action scope. A list of actions (or single action) 
      #     the rule will only be considered for.
      #   @option opts [Array<Symbol, String>, Symbol, String] :except Action scope. A list of actions (or single action)
      #     the rule will not be considered for.

      #   @option opts [Symbol, Class] :of Object for an object role check.
      #   @option opts [Symbol, Class] :for Synonym for +:of+
      #   @option opts [Symbol, Class] :in Synonym for +:of+
      #   @option opts [Symbol, Class] :on Synonym for +:of+
      #   @option opts [Symbol, Class] :at Synonym for +:of+
      #   @option opts [Symbol, Class] :by Synonym for +:of+
      # @see #all
      # @see #logged_in
      # @see #anonymous
      # @see #deny
      def allow(*args)
        rule(AllowRule, *args)
      end

      # Add a deny rule
      #
      # The {#deny} method has exactly same semantics as {#allow}. The only difference is that
      # access is denied when rule is matched, rather than allowed.
      #
      # @see #allow
      def deny(*args)
        rule(DenyRule, *args)
      end

      def actions(*args, &block)
        # TODO
        raise
      end

      alias action actions

      # Logged in pseudorole.
      #
      # Every user that has successfully logged in has this role. This is the opposite of {#anonymous}.
      #
      # @example Allow logged in users to request :index and :show actions in the controller. Access for not logged in (anonymous) users will be denied.
      #
      #   class SecretsController < ApplicationController
      #     access_control do
      #       allow logged_in, :to => [:index, :show]
      #     end
      #
      #     def index
      #       # ...
      #     end
      #
      #     def show
      #       # ...
      #     end
      #   end
      #
      # @see #anonymous
      # @see #all
      def logged_in; LOGGED_IN end

      # Anonymous pseudorole.
      #
      # Every not logged in user has this role. This is the opposite of {#logged_in}.
      #
      # @example Only allow anonymous users to log in.
      #
      #   class SecretsController < ApplicationController
      #     access_control do
      #       allow anonymous, :to => :login
      #       allow logged_in, :to => :logout
      #     end
      #
      #     def login
      #       # ...
      #     end
      #
      #     def logout
      #       # ...
      #     end
      #   end
      #
      # @see #logged_in
      # @see #all
      def anonymous; ANONYMOUS end

      # "All" pseudorole.
      #
      # Every user, either logged in or anonymous, has this role. Primarily used to allow access to actions
      # that should be widely accessible.
      #
      # @example Allow access to all actions
      #   class OpenController < ApplicationController
      #     access_control do   # Access control block could be completely omitted here
      #       allow all
      #     end
      #
      #     # ...
      #   end
      #
      # @example Readonly access
      #   class ProductsController < ApplicationController
      #     access_control do
      #       allow all, :to => [:index, :show]
      #       allow :admin                       # admin can also create, edit and destroy products
      #     end
      #
      #     # ...
      #   end
      def all; ALL end

      alias everyone all
      alias everybody all
      alias anyone all

      private

      VALID_PREPOSITIONS = %w(of for in on at by).freeze #unless defined? VALID_PREPOSITIONS

      def rule(rule_class, *args)
        options = args.extract_options!

        raise ArgumentError, "allow/deny should have at least 1 argument" if args.empty?

        # 1. Action scope (:to/:except)
        to = options.delete(:to)
        except = options.delete(:except)

        action_check = case
                       when to && !except
                         ActionCheck.new(to, false)
                       when !to && except
                         ActionCheck.new(except, true)
                       when to && except
                         raise ArgumentError, "both :to and :except cannot be specified in the rule"
                       end

        # 2. Object (:of/:for/...)
        object = nil

        VALID_PREPOSITIONS.each do |prep|
          if options[prep.to_sym]
            raise ArgumentError, "You may only use one preposition to specify object" if object

            object = options[prep.to_sym]
          end
        end

        unless [Class, Symbol, NilClass].any? { |klass| object.is_a? klass }
          raise ArgumentError, "object specified by preposition can only be a Class or a Symbol"
        end

        # 3. Rule condition (:if/:unless)
        _if = options.delete(:if)
        _unless = options.delete(:unless)

        unless [_if, _unless].all? { |cond| cond.nil? || cond.is_a?(Symbol) }
          raise ArgumentError, ":if/:unless option value must be a Symbol"
        end

        condition = DoubleCondition.new(_if, _unless) if (_if || _unless)

        @rules << rule_class.new(args, object, action_check, condition)
      end
    end
  end
end
